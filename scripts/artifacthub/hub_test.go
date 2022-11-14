package main

import (
	"os"
	"testing"
)

const (
	expectedHash = "dc888d5c05f7e0421a47adfe2d4e59b5264d6e56ec0b3392fe9b3d224bd61a3e"
)

func TestGetConstraintTemplateHash(t *testing.T) {
	testCases := []struct {
		name          string
		template      map[string]interface{}
		expectedHash  string
		expectedError bool
	}{
		{
			name: "valid hash",
			template: map[string]interface{}{
				"apiVersion": "constraints.gatekeeper.sh/v1beta1",
				"kind":       "K8sRequiredLabels",
				"metadata": map[string]interface{}{
					"name": "ns-must-have-gk",
				},
				"spec": map[string]interface{}{
					"match": map[string]interface{}{
						"kinds": []interface{}{
							map[string]interface{}{
								"apiGroups": []interface{}{"*"},
								"kinds":     []interface{}{"Namespace"},
							},
						},
					},
					"parameters": map[string]interface{}{
						"labels": []interface{}{"gatekeeper"},
					},
				},
			},
			expectedHash:  expectedHash,
			expectedError: false,
		},
		{
			name: "invalid hash",
			template: map[string]interface{}{
				"apiVersion": "constraints.gatekeeper.sh/v1beta1",
				"kind":       "K8sRequiredLabels",
				"metadata": map[string]interface{}{
					"name": "ns-must-have-gk",
				},
				"spec": map[string]interface{}{
					"match": map[string]interface{}{
						"kinds": []interface{}{
							map[string]interface{}{
								"apiGroups": []interface{}{"*"},
							},
						},
					},
				},
			},
			expectedHash:  expectedHash,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash := getConstraintTemplateHash(tc.template)
			if hash != tc.expectedHash && !tc.expectedError {
				t.Errorf("expected hash to be %s, got %s", tc.expectedHash, hash)
			}
		})
	}
}

func TestGetMetadataIfExist(t *testing.T) {

	testCases := []struct {
		name             string
		metadataFilePath string
		expectedNil      bool
	}{
		{
			name:             "invalid metadata file",
			metadataFilePath: "testdata/invalid-metadata.yaml",
			expectedNil:      true,
		},
		{
			name:             "valid metadata file",
			metadataFilePath: "testdata/artifacthub-pkg.yml",
			expectedNil:      false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := getMetadataIfExist(tc.metadataFilePath)
			if metadata == nil && !tc.expectedNil {
				t.Errorf("expected metadata not to be nil")
			}
		})
	}
}

func TestCopyDirectory(t *testing.T) {
	// create a temp directory
	srcDirPath, _ := os.MkdirTemp("", "src")
	defer os.RemoveAll(srcDirPath)

	// create a temp directory
	destDirPath, _ := os.MkdirTemp("", "dest")
	defer os.RemoveAll(destDirPath)

	// create a file in the src directory
	srcFilePath := srcDirPath + "/test.txt"
	os.WriteFile(srcFilePath, []byte("test"), 0o644)

	testCases := []struct {
		name          string
		src           string
		dst           string
		expectedError bool
		expectedText  func() string
	}{
		{
			name:          "invalid directory",
			src:           "invalid-src",
			dst:           destDirPath,
			expectedError: true,
		},
		{
			name:          "valid copy",
			src:           srcDirPath,
			dst:           destDirPath,
			expectedError: false,
			expectedText: func() string {
				// read the file in the dest directory
				destFilePath := destDirPath + "/test.txt"
				b, _ := os.ReadFile(destFilePath)
				return string(b)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := copyDirectory(tc.src, tc.dst)
			if err != nil && !tc.expectedError {
				t.Errorf("expected error to be nil")
			}

			if tc.expectedText != nil {
				if tc.expectedText() != "test" {
					t.Errorf("expected text to be 'test'")
				}
			}
		})
	}
}

func TestCheckVersion(t *testing.T) {
	testCases := []struct {
		name                      string
		artifactHubMetadata       *ArtifactHubMetadata
		constraintTemplate        map[string]interface{}
		newConstraintTemplateHash string
		expectedError             bool
	}{
		{
			name: "invalid version",
			artifactHubMetadata: &ArtifactHubMetadata{
				Digest:  "invalid-digest",
				Version: "v1.0.0",
			},
			newConstraintTemplateHash: "some-random-hash",
			constraintTemplate: map[string]interface{}{
				"metadata": map[string]interface{}{
					"annotations": map[string]interface{}{
						"metadata.gatekeeper.sh/version": "v1.0.0",
					},
				},
			},
			expectedError: true,
		},
		{
			name: "valid version with same digest",
			artifactHubMetadata: &ArtifactHubMetadata{
				Digest: "same-digest",
			},
			newConstraintTemplateHash: "same-digest",
			expectedError:             false,
		},
		{
			name: "valid version with different digest",
			artifactHubMetadata: &ArtifactHubMetadata{
				Digest:  "digest",
				Version: "v1.0.0",
			},
			newConstraintTemplateHash: "different-digest",
			constraintTemplate: map[string]interface{}{
				"metadata": map[string]interface{}{
					"annotations": map[string]interface{}{
						"metadata.gatekeeper.sh/version": "v1.0.1",
					},
				},
			},
			expectedError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkVersion(tc.artifactHubMetadata, tc.constraintTemplate, tc.newConstraintTemplateHash)
			if err != nil && !tc.expectedError {
				t.Errorf("expected error to be nil")
			}
		})
	}
}
