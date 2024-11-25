package aws_ebs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	configv1 "github.com/openshift/api/config/v1"
	fakeconfig "github.com/openshift/client-go/config/clientset/versioned/fake"
	"github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/csi-operator/pkg/clients"
)

func TestEBSVolumeTagsController_Sync(t *testing.T) {
	ctx := context.TODO()

	fakeConfigClient := fakeconfig.NewSimpleClientset()
	informerFactory := externalversions.NewSharedInformerFactory(fakeConfigClient, 0)
	informerFactory.Config().V1().Infrastructures().Informer()

	// Test getEC2Client with valid and invalid AWS credentials
	t.Run("TestGetEC2Client", func(t *testing.T) {
		fakeCoreClient := fake.NewSimpleClientset()

		// Case 1: Valid credentials
		validSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      awsEBSSecretName,
				Namespace: awsEBSSecretNamespace,
			},
			Data: map[string][]byte{
				"aws_access_key_id":     []byte("test-access-key"),
				"aws_secret_access_key": []byte("test-secret-key"),
			},
		}
		_, err := fakeCoreClient.CoreV1().Secrets(awsEBSSecretNamespace).Create(ctx, validSecret, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("Failed to create secret for valid credentials: %v", err)
		}

		controller := &EBSVolumeTagsController{
			commonClient: &clients.Clients{KubeClient: fakeCoreClient},
		}

		awsRegion := "us-east-1"
		ec2Client, err := controller.getEC2Client(ctx, awsRegion)
		if err != nil {
			t.Fatalf("Expected EC2 client to be created without errors for valid credentials, but got: %v", err)
		}
		if ec2Client == nil {
			t.Fatalf("Expected non-nil EC2 client, but got nil")
		}

		// Case 2: Missing credentials
		invalidSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      awsEBSSecretName,
				Namespace: awsEBSSecretNamespace,
			},
			Data: map[string][]byte{
				"some_other_field": []byte("some-value"),
			},
		}
		_, err = fakeCoreClient.CoreV1().Secrets(awsEBSSecretNamespace).Update(ctx, invalidSecret, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("Failed to create secret for invalid credentials: %v", err)
		}

		_, err = controller.getEC2Client(ctx, awsRegion)
		if err == nil {
			t.Fatalf("Expected error for missing AWS credentials, but got none")
		}
	})
}

// TestNewAndUpdatedTags checks that newAndUpdatedTags converts OpenShift AWS resource tags to AWS ec2.Tags correctly
func TestNewAndUpdatedTags(t *testing.T) {
	tests := []struct {
		name         string
		inputTags    []configv1.AWSResourceTag
		expectedTags []*ec2.Tag
	}{
		{
			name: "Single tag",
			inputTags: []configv1.AWSResourceTag{
				{Key: "key1", Value: "value1"},
			},
			expectedTags: []*ec2.Tag{
				{Key: aws.String("key1"), Value: aws.String("value1")},
			},
		},
		{
			name: "Multiple tags",
			inputTags: []configv1.AWSResourceTag{
				{Key: "key1", Value: "value1"},
				{Key: "key2", Value: "value2"},
			},
			expectedTags: []*ec2.Tag{
				{Key: aws.String("key1"), Value: aws.String("value1")},
				{Key: aws.String("key2"), Value: aws.String("value2")},
			},
		},
		{
			name:         "Empty tags",
			inputTags:    []configv1.AWSResourceTag{},
			expectedTags: []*ec2.Tag{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := newAndUpdatedTags(tt.inputTags)
			if len(result) != len(tt.expectedTags) {
				t.Fatalf("expected %d tags, got %d", len(tt.expectedTags), len(result))
			}

			for i, tag := range result {
				if *tag.Key != *tt.expectedTags[i].Key || *tag.Value != *tt.expectedTags[i].Value {
					t.Errorf("expected tag %v, got %v", tt.expectedTags[i], tag)
				}
			}
		})
	}
}

// TestVolumesIDsToResourceIDs checks that volumesIDsToResourceIDs converts a list of volume IDs to AWS resource IDs correctly
func TestVolumesIDsToResourceIDs(t *testing.T) {
	tests := []struct {
		name           string
		inputVolumeIDs []*v1.PersistentVolume
		expectedResult []*string
	}{
		{
			name: "pv-name",
			inputVolumeIDs: []*v1.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "PV1",
					},
					Spec: v1.PersistentVolumeSpec{
						PersistentVolumeSource: v1.PersistentVolumeSource{
							CSI: &v1.CSIPersistentVolumeSource{
								VolumeHandle: "vol-1234",
							},
						},
					},
				},
			},
			expectedResult: []*string{aws.String("vol-1234")},
		},
		{
			name: "Multiple volume IDs",
			inputVolumeIDs: []*v1.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "PV1",
					},
					Spec: v1.PersistentVolumeSpec{
						PersistentVolumeSource: v1.PersistentVolumeSource{
							CSI: &v1.CSIPersistentVolumeSource{
								VolumeHandle: "vol-1234",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "PV2",
					},
					Spec: v1.PersistentVolumeSpec{
						PersistentVolumeSource: v1.PersistentVolumeSource{
							CSI: &v1.CSIPersistentVolumeSource{
								VolumeHandle: "vol-5678",
							},
						},
					},
				},
			},
			expectedResult: []*string{aws.String("vol-1234"), aws.String("vol-5678")},
		},
		{
			name:           "No volume IDs",
			inputVolumeIDs: []*v1.PersistentVolume{},
			expectedResult: []*string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pvsToResourceIDs(tt.inputVolumeIDs)
			if len(result) != len(tt.expectedResult) {
				t.Fatalf("expected %d resource IDs, got %d", len(tt.expectedResult), len(result))
			}

			for i, resourceID := range result {
				if *resourceID != *tt.expectedResult[i] {
					t.Errorf("expected resource ID %s, got %s", *tt.expectedResult[i], *resourceID)
				}
			}
		})
	}
}

func TestFilterUpdatableVolumes(t *testing.T) {
	// Initialize the fake Kubernetes client
	fakeClientset := fake.NewSimpleClientset()

	// Initialize the controller with the fake clientset
	controller := EBSVolumeTagsController{
		commonClient: &clients.Clients{
			KubeClient: fakeClientset,
		},
	}

	newHash := "abcd"

	testCases := []struct {
		name             string
		pvs              []*v1.PersistentVolume
		newHash          string
		expectedInBatch  int
		expectedSerially int
	}{
		{
			name: "All volumes need update",
			pvs: []*v1.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "pv1",
						Annotations: map[string]string{},
					},
					Spec: v1.PersistentVolumeSpec{
						PersistentVolumeSource: v1.PersistentVolumeSource{
							CSI: &v1.CSIPersistentVolumeSource{Driver: driverName},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "pv2",
						Annotations: map[string]string{},
					},
					Spec: v1.PersistentVolumeSpec{
						PersistentVolumeSource: v1.PersistentVolumeSource{
							CSI: &v1.CSIPersistentVolumeSource{Driver: driverName},
						},
					},
				},
			},
			newHash:          newHash,
			expectedInBatch:  2,
			expectedSerially: 0,
		},
		{
			name: "Some volumes already updated",
			pvs: []*v1.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pv1",
						Annotations: map[string]string{
							tagHashAnnotationKey:         newHash,
							tagUpdateStatusAnnotationKey: tagUpdateStatusCompleted,
						},
					},
					Spec: v1.PersistentVolumeSpec{
						PersistentVolumeSource: v1.PersistentVolumeSource{
							CSI: &v1.CSIPersistentVolumeSource{Driver: driverName},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "pv2",
						Annotations: map[string]string{},
					},
					Spec: v1.PersistentVolumeSpec{
						PersistentVolumeSource: v1.PersistentVolumeSource{
							CSI: &v1.CSIPersistentVolumeSource{Driver: driverName},
						},
					},
				},
			},
			newHash:          newHash,
			expectedInBatch:  1,
			expectedSerially: 0,
		},
		{
			name: "Volumes require serial updates",
			pvs: []*v1.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pv1",
						Annotations: map[string]string{
							tagHashAnnotationKey: newHash,
						},
					},
					Spec: v1.PersistentVolumeSpec{
						PersistentVolumeSource: v1.PersistentVolumeSource{
							CSI: &v1.CSIPersistentVolumeSource{Driver: driverName},
						},
					},
				},
			},
			newHash:          newHash,
			expectedInBatch:  0,
			expectedSerially: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.TODO()

			// Preload the fake client with the test PVs
			for _, pv := range tc.pvs {
				_, err := fakeClientset.CoreV1().PersistentVolumes().Get(ctx, pv.Name, metav1.GetOptions{})
				if err != nil && errors.IsNotFound(err) {
					// If PV doesn't exist, create it
					_, err = fakeClientset.CoreV1().PersistentVolumes().Create(ctx, pv, metav1.CreateOptions{})
					if err != nil {
						t.Fatalf("Failed to add test PV to fake client: %v", err)
					}
				}

			}

			// Call filterUpdatableVolumes method to test
			inBatch, serially := controller.filterUpdatableVolumes(ctx, tc.pvs, tc.newHash)

			// Use standard Go assertions
			if len(inBatch) != tc.expectedInBatch {
				t.Errorf("Expected %d batch updatable volumes, got %d", tc.expectedInBatch, len(inBatch))
			}
			if len(serially) != tc.expectedSerially {
				t.Errorf("Expected %d serially updatable volumes, got %d", tc.expectedSerially, len(serially))
			}
		})
	}
}

func TestGetPVTagHash(t *testing.T) {
	// Test: PV with tag hash
	tagHashPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tag-hash-pv",
			Annotations: map[string]string{
				tagHashAnnotationKey: "test-hash",
			},
		},
	}

	// Test: PV without tag hash
	noTagHashPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "no-tag-hash-pv",
			Annotations: map[string]string{},
		},
	}

	tests := []struct {
		name         string
		pv           *corev1.PersistentVolume
		expectedHash string
	}{
		{
			name:         "PV with tag hash",
			pv:           tagHashPV,
			expectedHash: "test-hash",
		},
		{
			name:         "PV without tag hash",
			pv:           noTagHashPV,
			expectedHash: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := getPVTagHash(tt.pv)
			if hash != tt.expectedHash {
				t.Errorf("Expected hash %q, got %q", tt.expectedHash, hash)
			}
		})
	}
}

func TestGetPVTagUpdateStatus(t *testing.T) {
	// Test: PV with tag update status
	tagUpdateStatusPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tag-update-status-pv",
			Annotations: map[string]string{
				tagUpdateStatusAnnotationKey: tagUpdateStatusInProgress,
			},
		},
	}

	// Test: PV without tag update status
	noTagUpdateStatusPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "no-tag-update-status-pv",
			Annotations: map[string]string{},
		},
	}

	tests := []struct {
		name           string
		pv             *corev1.PersistentVolume
		expectedStatus string
	}{
		{
			name:           "PV with tag update status",
			pv:             tagUpdateStatusPV,
			expectedStatus: tagUpdateStatusInProgress,
		},
		{
			name:           "PV without tag update status",
			pv:             noTagUpdateStatusPV,
			expectedStatus: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := getPVTagUpdateStatus(tt.pv)
			if status != tt.expectedStatus {
				t.Errorf("Expected status %q, got %q", tt.expectedStatus, status)
			}
		})
	}
}

func TestNewAndUpdatedTagsSpecialCharacters(t *testing.T) {
	tests := []struct {
		name         string
		inputTags    []configv1.AWSResourceTag
		expectedTags []*ec2.Tag
	}{
		{
			name: "Tags with special characters",
			inputTags: []configv1.AWSResourceTag{
				{Key: "key-1", Value: "value_1"},
				{Key: "key:with:colon", Value: "value@with@at"},
			},
			expectedTags: []*ec2.Tag{
				{Key: aws.String("key-1"), Value: aws.String("value_1")},
				{Key: aws.String("key:with:colon"), Value: aws.String("value@with@at")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := newAndUpdatedTags(tt.inputTags)
			if len(result) != len(tt.expectedTags) {
				t.Fatalf("expected %d tags, got %d", len(tt.expectedTags), len(result))
			}

			for i, tag := range result {
				if *tag.Key != *tt.expectedTags[i].Key || *tag.Value != *tt.expectedTags[i].Value {
					t.Errorf("expected tag %v, got %v", tt.expectedTags[i], tag)
				}
			}
		})
	}
}

func TestMarkVolumeTagsUpdateInProgress(t *testing.T) {
	ctx := context.TODO()
	fakeCoreClient := fake.NewSimpleClientset()

	controller := &EBSVolumeTagsController{
		commonClient: &clients.Clients{KubeClient: fakeCoreClient},
	}

	testPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-pv",
			Annotations: map[string]string{},
		},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{Driver: driverName},
			},
		},
	}

	// create a testPV to test status.
	_, err := fakeCoreClient.CoreV1().PersistentVolumes().Create(ctx, testPV, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to add test PV to fake client: %v", err)
	}

	// Simulate marking volume tags update in progress
	newHash := "test-new-hash"
	updatedPV, err := controller.markVolumeTagsUpdateInProgress(ctx, testPV, newHash)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check if the annotations were updated correctly
	if updatedPV.Annotations[tagHashAnnotationKey] != newHash {
		t.Errorf("Expected tag-hash to be %q, got %q", newHash, updatedPV.Annotations["ebs.openshift/tag-hash"])
	}
	if updatedPV.Annotations[tagUpdateStatusAnnotationKey] != tagUpdateStatusInProgress {
		t.Errorf("Expected tag-update-status to be 'in-progress', got %q", updatedPV.Annotations["ebs.openshift/tag-update-status"])
	}
}

func TestMarkVolumeTagsUpdateStatusCompleted(t *testing.T) {
	ctx := context.TODO()
	fakeCoreClient := fake.NewSimpleClientset()

	controller := &EBSVolumeTagsController{
		commonClient: &clients.Clients{KubeClient: fakeCoreClient},
	}

	// Create a test PersistentVolume with initial annotations
	testPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-pv",
			Annotations: map[string]string{},
		},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{Driver: driverName},
			},
		},
	}

	// Add the testPV to the fake client
	_, err := fakeCoreClient.CoreV1().PersistentVolumes().Create(ctx, testPV, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to add test PV to fake client: %v", err)
	}

	// Simulate marking volume tags update status as completed
	updatedPV, err := controller.markVolumeTagsUpdateStatusCompleted(ctx, testPV)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check if the annotations were updated correctly
	if updatedPV.Annotations[tagUpdateStatusAnnotationKey] != tagUpdateStatusCompleted {
		t.Errorf("Expected tag-update-status to be '%s', got '%s'", tagUpdateStatusCompleted, updatedPV.Annotations[tagUpdateStatusAnnotationKey])
	}
}

func TestComputeTagsHash(t *testing.T) {
	tests := []struct {
		name         string
		resourceTags []configv1.AWSResourceTag
		expectedHash string
	}{
		{
			name: "Single tag",
			resourceTags: []configv1.AWSResourceTag{
				{Key: "key1", Value: "value1"},
			},
			expectedHash: computeSHA256("key1=value1;"), // Compute hash directly for test validation
		},
		{
			name: "Multiple tags, unsorted",
			resourceTags: []configv1.AWSResourceTag{
				{Key: "key2", Value: "value2"},
				{Key: "key1", Value: "value1"},
			},
			expectedHash: computeSHA256("key1=value1;key2=value2;"),
		},
		{
			name:         "Empty tags",
			resourceTags: []configv1.AWSResourceTag{},
			expectedHash: computeSHA256(""),
		},
		{
			name: "Duplicate keys with different values",
			resourceTags: []configv1.AWSResourceTag{
				{Key: "key1", Value: "value1"},
				{Key: "key1", Value: "value2"},
			},
			expectedHash: computeSHA256("key1=value1;key1=value2;"),
		},
		{
			name: "Special characters in keys and values",
			resourceTags: []configv1.AWSResourceTag{
				{Key: "key-with-dash", Value: "value_with_underscore"},
				{Key: "key/with/slash", Value: "value:with:colon"},
			},
			expectedHash: computeSHA256("key-with-dash=value_with_underscore;key/with/slash=value:with:colon;"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := computeTagsHash(tt.resourceTags)
			if hash != tt.expectedHash {
				t.Errorf("Expected hash %q, got %q", tt.expectedHash, hash)
			}
		})
	}
}

// Helper function to compute SHA256 hash for test validation
func computeSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}
