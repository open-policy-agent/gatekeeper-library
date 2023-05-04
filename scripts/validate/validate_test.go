package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateDocsDirStructure(t *testing.T) {
	testCases := []struct {
		name         string
		dirStructure []string
		expectedErr  bool
	}{
		{
			name:         "Valid directory structure",
			dirStructure: []string{"mutation-examples", "validation", "intro.md", "pspintro.md"},
			expectedErr:  false,
		},
		{
			name:         "Unexpected directory",
			dirStructure: []string{"mutation-examples", "unexpected-dir", "validation", "intro.md", "pspintro.md"},
			expectedErr:  true,
		},
		{
			name:         "Unexpected file",
			dirStructure: []string{"mutation-examples", "validation", "unexpected-file.md", "intro.md", "pspintro.md"},
			expectedErr:  true,
		},
		{
			name:         "Missing file",
			dirStructure: []string{"mutation-examples", "validation", "intro.md"},
			expectedErr:  true,
		},
		{
			name:         "Missing directory",
			dirStructure: []string{"mutation-examples", "intro.md", "pspintro.md"},
			expectedErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a temporary directory for testing
			tmpDir, err := os.MkdirTemp("", "test")
			if err != nil {
				t.Fatalf("Error creating temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			// Create the directory structure
			docsDirPath := filepath.Join(tmpDir, docsDirEntry)
			err = os.MkdirAll(docsDirPath, 0o755)
			if err != nil {
				t.Fatalf("Error creating docs dir: %v", err)
			}
			for _, item := range tc.dirStructure {
				path := filepath.Join(docsDirPath, item)
				if filepath.Ext(path) == "" {
					if os.Mkdir(path, 0o755) != nil {
						t.Fatalf("Error creating directory: %v", path)
					}
				} else {
					f, err := os.Create(path)
					if err != nil {
						t.Fatalf("Error creating the file %s: %v", item, err)
					}
					defer f.Close()

					_, err = f.Write([]byte{})
					if err != nil {
						t.Fatalf("Error writing to the file %s: %v", item, err)
					}
				}
			}

			err = validateDocsDirStructure(tmpDir)
			if tc.expectedErr && err == nil {
				t.Errorf("Expected error, but got nil")
			}
		})
	}
}

func TestContains(t *testing.T) {
	testCases := []struct {
		name     string
		items    []string
		item     string
		expected bool
	}{
		{
			name:     "Item in list",
			items:    []string{"item1", "item2", "item3"},
			item:     "item2",
			expected: true,
		},
		{
			name:     "Item not in list",
			items:    []string{"item1", "item2", "item3"},
			item:     "item4",
			expected: false,
		},
		{
			name:     "list is empty",
			items:    []string{},
			item:     "foo",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := contains(tc.items, tc.item)
			if result != tc.expected {
				t.Errorf("Expected %v, but got %v", tc.expected, result)
			}
		})
	}
}
