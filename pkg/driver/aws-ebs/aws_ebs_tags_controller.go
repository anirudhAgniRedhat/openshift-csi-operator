package aws_ebs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/time/rate"
	"os"
	"sort"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"

	configv1 "github.com/openshift/api/config/v1"
	operatorapi "github.com/openshift/api/operator/v1"
	"github.com/openshift/csi-operator/pkg/clients"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
)

const (
	awsEBSSecretNamespace        = "openshift-cluster-csi-drivers"
	awsEBSSecretName             = "ebs-cloud-credentials"
	driverName                   = "ebs.csi.aws.com"
	tagHashAnnotationKey         = "ebs.openshift.io/volume-tags-hash"
	tagUpdateStatusAnnotationKey = "ebs.openshift.io/volume-tags-update-status"
	tagUpdateStatusCompleted     = "COMPLETED"
	tagUpdateStatusInProgress    = "IN-PROGRESS"
	batchSize                    = 50
	maxCreateTagsPerSecond       = 100 // Maximum CreateTags API requests per second

	operationDelay         = 2 * time.Second
	operationBackoffFactor = 1.2
	operationRetryCount    = 5
)

type EBSVolumeTagsController struct {
	name          string
	commonClient  *clients.Clients
	eventRecorder events.Recorder
	rateLimiter   *rate.Limiter
}

func NewEBSVolumeTagsController(
	name string,
	commonClient *clients.Clients,
	eventRecorder events.Recorder) factory.Controller {

	c := &EBSVolumeTagsController{
		name:          name,
		commonClient:  commonClient,
		eventRecorder: eventRecorder,
		rateLimiter:   rate.NewLimiter(rate.Limit(maxCreateTagsPerSecond), maxCreateTagsPerSecond), // Allow burst up to the limit
	}
	return factory.New().WithSync(
		c.Sync,
	).ResyncEvery(
		20*time.Minute,
	).WithInformers(
		c.commonClient.ConfigInformers.Config().V1().Infrastructures().Informer(),
	).ToController(
		name,
		eventRecorder,
	)
}

func (c *EBSVolumeTagsController) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	klog.Infof("EBSVolumeTagsController sync started")
	defer klog.Infof("EBSVolumeTagsController sync finished")

	opSpec, _, _, err := c.commonClient.OperatorClient.GetOperatorState()
	if err != nil {
		return err
	}
	if opSpec.ManagementState != operatorapi.Managed {
		return nil
	}

	infra, err := c.getInfrastructure()
	if err != nil {
		return err
	}
	if infra == nil {
		return nil
	}
	err = c.processEBSVolumesTagsUpdate(ctx, infra)
	if err != nil {
		return err
	}

	return nil
}

func (c *EBSVolumeTagsController) processEBSVolumesTagsUpdate(ctx context.Context, infra *configv1.Infrastructure) error {
	if infra.Status.PlatformStatus == nil || infra.Status.PlatformStatus.AWS == nil ||
		infra.Status.PlatformStatus.AWS.ResourceTags == nil || len(infra.Status.PlatformStatus.AWS.ResourceTags) == 0 {
		return nil
	}
	pvs, err := c.listPersistentVolumes()
	if err != nil {
		return err
	}
	newHash := computeTagsHash(infra.Status.PlatformStatus.AWS.ResourceTags)
	batchUpdatableVolumes, seriallyUpdatableVolumes := c.filterUpdatableVolumes(ctx, pvs, newHash)
	if len(batchUpdatableVolumes) == 0 && len(seriallyUpdatableVolumes) == 0 {
		klog.Infof("no volume tags needs to be updates")
		return nil
	}
	ec2Client, err := c.getEC2Client(ctx, infra.Status.PlatformStatus.AWS.Region)
	if err != nil {
		klog.Errorf("Failed to get EC2 client: %v", err)
		return err
	}
	err = c.batchUpdateVolumesTags(ctx, ec2Client, infra, batchUpdatableVolumes)
	if err != nil {
		klog.Errorf("failed to update tags for EBS volumes batch: %v", err)
	}
	err = c.seriallyUpdateVolumesTags(ctx, ec2Client, infra, seriallyUpdatableVolumes)
	if err != nil {
		klog.Errorf("failed to update tags for EBS volumes serially: %v", err)
	}
	return nil
}

// getEC2Client retrieves AWS credentials from the secret and creates an AWS EC2 client using session.Options
func (c *EBSVolumeTagsController) getEC2Client(ctx context.Context, awsRegion string) (*ec2.EC2, error) {
	secret, err := c.getEBSCloudCredSecret(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving AWS credentials secret: %v", err)
	}

	// Check for aws_access_key_id and aws_secret_access_key fields
	awsAccessKeyID, accessKeyFound := secret.Data["aws_access_key_id"]
	awsSecretAccessKey, secretKeyFound := secret.Data["aws_secret_access_key"]

	if accessKeyFound && secretKeyFound {
		return createEC2ClientWithStaticKeys(awsRegion, string(awsAccessKeyID), string(awsSecretAccessKey))
	}

	// Otherwise, check for credentials field and create session using that
	credentialsData, credentialsFound := secret.Data["credentials"]
	if credentialsFound {
		tempFile, err := writeCredentialsToTempFile(credentialsData)
		if err != nil {
			return nil, fmt.Errorf("error writing credentials to temporary file: %v", err)
		}

		return createEC2ClientWithCredentialsFile(awsRegion, tempFile)
	}

	return nil, fmt.Errorf("no valid AWS credentials found in secret")
}

// createEC2ClientWithStaticKeys creates an EC2 client using static credentials (access key and secret key)
func createEC2ClientWithStaticKeys(awsRegion, awsAccessKeyID, awsSecretAccessKey string) (*ec2.EC2, error) {
	awsSession, err := session.NewSession(&aws.Config{
		Region:      aws.String(awsRegion),
		Credentials: credentials.NewStaticCredentials(awsAccessKeyID, awsSecretAccessKey, ""),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating AWS session with static credentials: %v", err)
	}
	return ec2.New(awsSession), nil
}

// createEC2ClientWithCredentialsFile creates an EC2 client using a temporary credentials file
func createEC2ClientWithCredentialsFile(awsRegion, credentialsFilename string) (*ec2.EC2, error) {
	klog.Infof("Creating AWS session using credentials file: %s", credentialsFilename)

	defer func() {
		err := os.Remove(credentialsFilename)
		if err != nil {
			klog.Warningf("Failed to remove temporary credentials file: %v", err)
		} else {
			klog.Infof("Temporary credentials file %s removed successfully.", credentialsFilename)
		}
	}()

	awsOptions := session.Options{
		Config: aws.Config{
			Region: aws.String(awsRegion),
		},
		SharedConfigState: session.SharedConfigEnable,
		SharedConfigFiles: []string{credentialsFilename},
	}

	awsSession, err := session.NewSessionWithOptions(awsOptions)
	if err != nil {
		return nil, fmt.Errorf("error creating AWS session using credentials file: %v", err)
	}

	return ec2.New(awsSession), nil
}

// writeCredentialsToTempFile writes credentials data to a temporary file and returns the filename
func writeCredentialsToTempFile(data []byte) (string, error) {
	f, err := os.CreateTemp("", "aws-shared-credentials")
	if err != nil {
		return "", fmt.Errorf("failed to create file for shared credentials: %v", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		defer os.Remove(f.Name())
		return "", fmt.Errorf("failed to write credentials to %s: %v", f.Name(), err)
	}
	return f.Name(), nil
}

// getInfrastructure retrieves the Infrastructure resource in OpenShift
func (c *EBSVolumeTagsController) getInfrastructure() (*configv1.Infrastructure, error) {
	infra, err := c.commonClient.ConfigInformers.Config().V1().Infrastructures().Lister().Get(infrastructureName)
	if err != nil {
		klog.Errorf("error listing infrastructures objects: %v", err)
		return nil, err
	}
	return infra, err
}

func (c *EBSVolumeTagsController) getEBSCloudCredSecret(ctx context.Context) (*v1.Secret, error) {
	backoff := wait.Backoff{
		Duration: operationDelay,
		Factor:   operationBackoffFactor,
		Steps:    operationRetryCount,
	}
	var awsCreds *v1.Secret
	err := wait.ExponentialBackoffWithContext(ctx, backoff, func(ctx context.Context) (bool, error) {
		var apiError error
		awsCreds, apiError = c.commonClient.KubeClient.CoreV1().Secrets(awsEBSSecretNamespace).
			Get(ctx, awsEBSSecretName, metav1.GetOptions{})
		if apiError != nil {
			klog.Errorf("error getting secret object: %v", apiError)
			return false, nil
		}
		if awsCreds != nil {
			return true, nil
		}
		return false, nil
	})
	return awsCreds, err

}

func (c *EBSVolumeTagsController) filterUpdatableVolumes(ctx context.Context, pvs []*v1.PersistentVolume,
	newHash string) ([]*v1.PersistentVolume, []*v1.PersistentVolume) {
	updatableVolumesInBatch := make([]*v1.PersistentVolume, 0)
	updatableVolumesSerially := make([]*v1.PersistentVolume, 0)
	for _, pv := range pvs {
		if pv.Spec.CSI != nil && pv.Spec.CSI.Driver == driverName {
			annotationHash := getPVTagHash(pv)
			if annotationHash == "" || annotationHash != newHash {
				updatedPv, err := c.markVolumeTagsUpdateInProgress(ctx, pv, newHash)
				if err != nil {
					klog.Errorf("Failed to mark volume %s as updated in progress: %v", pv.Name, err)
					continue
				}
				updatableVolumesInBatch = append(updatableVolumesInBatch, updatedPv)
			} else if annotationHash == newHash && getPVTagUpdateStatus(pv) != tagUpdateStatusCompleted {
				updatableVolumesSerially = append(updatableVolumesSerially, pv)
			}
		}
	}
	return updatableVolumesInBatch, updatableVolumesSerially
}

func (c *EBSVolumeTagsController) batchUpdateVolumesTags(ctx context.Context, ec2Client *ec2.EC2,
	infra *configv1.Infrastructure, updatableVolumes []*v1.PersistentVolume) error {
	if len(updatableVolumes) == 0 {
		klog.Infof("No batch updatable PVs found for EBS volume")
		return nil
	}
	// Process the volumes in batches
	for i := 0; i < len(updatableVolumes); i += batchSize {
		end := i + batchSize
		if end > len(updatableVolumes) {
			end = len(updatableVolumes)
		}
		batch := updatableVolumes[i:end]

		// Update tags on AWS EBS volumes
		err := c.updateBatchEBSTags(batch, ec2Client, infra.Status.PlatformStatus.AWS.ResourceTags)
		if err != nil {
			c.handleBatchTagUpdateFailure(batch, err)
			continue
		}

		// Update PV annotations after successfully updating the tags in AWS
		for _, volume := range batch {
			_, err = c.markVolumeTagsUpdateStatusCompleted(ctx, volume)
			if err != nil {
				klog.Errorf("Error updating PV annotations for volume %s: %v", volume.Name, err)
				continue
			}
			klog.Infof("Successfully updated PV annotations and tags for volume %s", volume.Name)
		}
	}
	return nil
}

func (c *EBSVolumeTagsController) seriallyUpdateVolumesTags(ctx context.Context, ec2Client *ec2.EC2,
	infra *configv1.Infrastructure, updatableVolumes []*v1.PersistentVolume) error {
	if len(updatableVolumes) == 0 {
		klog.Infof("No serially updatable PVs found for EBS volume")
		return nil
	}
	for _, volume := range updatableVolumes {
		err := c.updateSerialEBSTags(volume, ec2Client, infra.Status.PlatformStatus.AWS.ResourceTags)
		if err != nil {
			c.handleSingleTagUpdateFailure(volume, err)
			continue
		}
		_, err = c.markVolumeTagsUpdateStatusCompleted(ctx, volume)
		if err != nil {
			klog.Errorf("Error updating PV annotations for volume %s: %v", volume.Name, err)
			continue
		}
		klog.Infof("Successfully updated tags and annotation for volume %s", volume.Name)
	}
	return nil
}

// updateBatchEBSTags updates the tags of an AWS EBS volume batches.
func (c *EBSVolumeTagsController) updateBatchEBSTags(pvBatch []*v1.PersistentVolume, ec2Client *ec2.EC2,
	resourceTags []configv1.AWSResourceTag) error {
	tags := newAndUpdatedTags(resourceTags)

	// Wait for rate limiter
	err := c.rateLimiter.Wait(context.Background())
	if err != nil {
		return fmt.Errorf("rate limiter wait error: %v", err)
	}

	// Create or update the tags
	_, err = ec2Client.CreateTags(&ec2.CreateTagsInput{
		Resources: pvsToResourceIDs(pvBatch),
		Tags:      tags,
	})
	if err != nil {
		return err
	}
	return nil
}

// updateSerialEBSTags updates the tags of single AWS EBS volume.
func (c *EBSVolumeTagsController) updateSerialEBSTags(pv *v1.PersistentVolume, ec2Client *ec2.EC2,
	resourceTags []configv1.AWSResourceTag) error {
	tags := newAndUpdatedTags(resourceTags)

	// Wait for rate limiter
	err := c.rateLimiter.Wait(context.Background())
	if err != nil {
		return fmt.Errorf("rate limiter wait error: %v", err)
	}

	// Create or update the tags
	_, err = ec2Client.CreateTags(&ec2.CreateTagsInput{
		Resources: []*string{aws.String(pv.Spec.CSI.VolumeHandle)},
		Tags:      tags,
	})
	if err != nil {
		return err
	}
	return nil
}

func (c *EBSVolumeTagsController) markVolumeTagsUpdateInProgress(ctx context.Context, pv *v1.PersistentVolume,
	hash string) (*v1.PersistentVolume, error) {
	// Create a deep copy of the PersistentVolume to avoid modifying the cached object
	pvCopy := pv.DeepCopy()

	// Ensure the PV has an annotations map
	if pvCopy.Annotations == nil {
		pvCopy.Annotations = make(map[string]string)
	}

	pvCopy.Annotations[tagHashAnnotationKey] = hash
	pvCopy.Annotations[tagUpdateStatusAnnotationKey] = tagUpdateStatusInProgress

	newPv, err := c.commonClient.KubeClient.CoreV1().PersistentVolumes().Update(ctx, pvCopy, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	return newPv, nil
}

func (c *EBSVolumeTagsController) markVolumeTagsUpdateStatusCompleted(ctx context.Context, pv *v1.PersistentVolume) (
	*v1.PersistentVolume, error) {
	// Create a deep copy of the PersistentVolume to avoid modifying the cached object
	pvCopy := pv.DeepCopy()

	// Ensure the PV has an annotations map
	if pvCopy.Annotations == nil {
		pvCopy.Annotations = make(map[string]string)
	}
	pvCopy.Annotations[tagUpdateStatusAnnotationKey] = tagUpdateStatusCompleted

	newPv, err := c.commonClient.KubeClient.CoreV1().PersistentVolumes().Update(ctx, pvCopy, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	return newPv, nil
}

func (c *EBSVolumeTagsController) listPersistentVolumes() ([]*v1.PersistentVolume, error) {
	pvList, err := c.commonClient.KubeInformers.InformersFor("").Core().V1().
		PersistentVolumes().Lister().List(labels.Everything())
	if err != nil {
		klog.Errorf("error listing volumes objects: %v", err)
		return nil, err
	}
	return pvList, nil
}

func (c *EBSVolumeTagsController) handleBatchTagUpdateFailure(batch []*v1.PersistentVolume, updateErr error) {
	for _, pv := range batch {
		klog.Errorf("Error updating volume %v tags: %v", pv.Name, updateErr)
	}
	var pvNames []string
	for _, pv := range batch {
		pvNames = append(pvNames, pv.Name)
	}
	errorMessage := fmt.Sprintf("Error updating tags for volume %v: %v", pvNames, updateErr)
	// Emit a warning event for the failure
	c.eventRecorder.Warning("EBSVolumeTagsUpdateFailed",
		fmt.Sprintf("Failed to update tags for batch %v: %v", pvNames, errorMessage))
}

func (c *EBSVolumeTagsController) handleSingleTagUpdateFailure(pv *v1.PersistentVolume, updateErr error) {
	klog.Errorf("Error updating tags for volume %v: %v", pv.Name, updateErr)
	errorMessage := fmt.Sprintf("Error updating tags for volume %v: %v", pv.Name, updateErr)
	// Emit a warning event for the failure
	c.eventRecorder.Warning("EBSVolumeTagsUpdateFailed",
		fmt.Sprintf("Failed to update tags for batch %v: %v", pv.Name, errorMessage))
}

// newAndUpdatedTags adds and update existing AWS tags with new resource tags from OpenShift infrastructure
func newAndUpdatedTags(resourceTags []configv1.AWSResourceTag) []*ec2.Tag {
	// Convert map back to slice of ec2.Tag
	var tags []*ec2.Tag
	for _, tag := range resourceTags {
		tags = append(tags, &ec2.Tag{
			Key:   aws.String(tag.Key),
			Value: aws.String(tag.Value),
		})
	}
	return tags
}

func pvsToResourceIDs(volumes []*v1.PersistentVolume) []*string {
	var resourceIDs []*string
	for _, volume := range volumes {
		resourceIDs = append(resourceIDs, aws.String(volume.Spec.CSI.VolumeHandle))
	}
	return resourceIDs
}

// getPVTagHash gets the hash stored in the PV annotations.
// If no annotation is found, it returns an empty string, indicating no tags have been applied yet.
func getPVTagHash(pv *v1.PersistentVolume) string {
	// Check if the annotation exists
	if hash, found := pv.Annotations[tagHashAnnotationKey]; found {
		return hash
	}
	// If no annotation is found, return an empty string
	return ""
}

func getPVTagUpdateStatus(pv *v1.PersistentVolume) string {
	if status, found := pv.Annotations[tagUpdateStatusAnnotationKey]; found {
		return status
	}
	// If no annotation is found, return an empty string
	return ""
}

// computeTagsHash computes a hash for the sorted resource tags.
func computeTagsHash(resourceTags []configv1.AWSResourceTag) string {
	// Sort tags by key for consistency
	sort.Slice(resourceTags, func(i, j int) bool {
		return resourceTags[i].Key < resourceTags[j].Key
	})

	// Create a string representation of the sorted tags
	var tagsString string
	for _, tag := range resourceTags {
		tagsString += tag.Key + "=" + tag.Value + ";"
	}

	// Compute SHA256 hash of the tags string
	hash := sha256.Sum256([]byte(tagsString))
	return hex.EncodeToString(hash[:])
}
