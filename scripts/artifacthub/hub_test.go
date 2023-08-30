package main

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	expectedHash = "dc888d5c05f7e0421a47adfe2d4e59b5264d6e56ec0b3392fe9b3d224bd61a3e" //nolint
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
	if os.WriteFile(srcFilePath, []byte("test"), 0o600) != nil {
		t.Errorf("error writing file")
	}

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

// MockClient is a mock implementation of the HTTPClient interface for testing.
type MockClient struct {
	Resp *http.Response
	Err  error
}

// Get is a method of MockClient that returns the pre-configured response and error.
func (c MockClient) Get(_ string) (*http.Response, error) {
	return c.Resp, c.Err
}

func TestCheckVersion(t *testing.T) {
	testCases := []struct {
		name                     string
		artifactHubMetadata      *ArtifactHubMetadata
		httpStatus               int
		httpError                error
		githubConstraintTemplate map[string]interface{}
		expectedErrorMessage     string
	}{
		{
			name: "invalid version",
			artifactHubMetadata: &ArtifactHubMetadata{
				Digest:  "invalid-digest",
				Version: "v1.0.0",
			},
			httpStatus: http.StatusOK,
			githubConstraintTemplate: map[string]interface{}{
				"metadata": map[string]interface{}{
					"annotations": map[string]interface{}{
						"metadata.gatekeeper.sh/version": "v1.0.0",
					},
				},
			},
			expectedErrorMessage: "looks like template.yaml is updated but the version is not. Please update the 'metadata.gatekeeper.sh/version' annotation in the template.yaml source",
		},
		{
			name: "valid version with same digest",
			artifactHubMetadata: &ArtifactHubMetadata{
				Digest: "600ca4d7048b1b64a5d80aaabf015eceef5d613c2f5a0a3d31e5360535d3c6e8",
			},
			httpStatus: http.StatusOK,
			githubConstraintTemplate: map[string]interface{}{
				"metadata": map[string]interface{}{
					"annotations": map[string]interface{}{
						"metadata.gatekeeper.sh/version": "v1.0.0",
					},
				},
			},
		},
		{
			name: "valid version bump with different digest",
			artifactHubMetadata: &ArtifactHubMetadata{
				Digest:  "digest",
				Version: "v1.0.1",
			},
			httpStatus: http.StatusOK,
			githubConstraintTemplate: map[string]interface{}{
				"metadata": map[string]interface{}{
					"annotations": map[string]interface{}{
						"metadata.gatekeeper.sh/version": "v1.0.0",
					},
				},
			},
		},
		{
			name:       "template not found",
			httpStatus: http.StatusNotFound,
		},
		{
			name:                 "get template error",
			httpStatus:           http.StatusOK,
			httpError:            errors.New("fake error"),
			expectedErrorMessage: "error while getting constraint template from github: fake error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			githubConstraintTemplateBytes, _ := yaml.Marshal(tc.githubConstraintTemplate)

			// Create a mock client with a pre-configured response and error.
			mockResp := &http.Response{
				StatusCode: tc.httpStatus,
				Body:       io.NopCloser(strings.NewReader(string(githubConstraintTemplateBytes))),
			}
			mockClient := MockClient{
				Resp: mockResp,
				Err:  tc.httpError,
			}

			err := checkVersion(mockClient, tc.artifactHubMetadata, "path/to/constraint/template.yaml")

			if tc.expectedErrorMessage != "" {
				if err == nil {
					t.Errorf("Expected error '%s', but got no error", tc.expectedErrorMessage)
				} else if err.Error() != tc.expectedErrorMessage {
					t.Errorf("Expected error '%s', but got '%s'", tc.expectedErrorMessage, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got '%s'", err.Error())
				}
			}
		})
	}
}
