package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	docsDirEntry = "website/docs"
)

func main() {
	pwd, err := os.Getwd()
	if err != nil {
		fmt.Println("error while getting pwd")
		panic(err)
	}
	rootDir := filepath.Join(pwd, "..", "..")

	err = validateDocsDirStructure(rootDir)
	if err != nil {
		fmt.Println("error while validating docs directory structure")
		panic(err)
	}
}

func validateDocsDirStructure(rootDir string) error {
	docsDirPath := filepath.Join(rootDir, docsDirEntry)
	// expected directory structure
	expectedDirs := []string{"mutation-examples", "validation"}
	expectedFiles := []string{"intro.md", "pspintro.md"}

	// Get the list of files and directories in the docs directory
	files, err := os.ReadDir(docsDirPath)
	if err != nil {
		return err
	}

	// Validate the directory structure
	for _, file := range files {
		if file.IsDir() {
			if !contains(expectedDirs, file.Name()) {
				err = fmt.Errorf("unexpected directory: %s, found at: %s", file.Name(), filepath.Join(docsDirPath, file.Name()))
				return err
			}
		} else {
			if !contains(expectedFiles, file.Name()) {
				err = fmt.Errorf("unexpected file: %s, found at: %s", file.Name(), filepath.Join(docsDirPath, file.Name()))
				return err
			}
		}
	}

	// Check for missing directories and files
	for _, expectedDir := range expectedDirs {
		if _, err := os.Stat(filepath.Join(docsDirPath, expectedDir)); os.IsNotExist(err) {
			err = fmt.Errorf("missing directory: %s", expectedDir)
			return err
		}
	}

	for _, expectedFile := range expectedFiles {
		if _, err := os.Stat(filepath.Join(docsDirPath, expectedFile)); os.IsNotExist(err) {
			err = fmt.Errorf("missing file: %s", expectedFile)
			return err
		}
	}

	return nil
}

func contains(items []string, item string) bool {
	for _, i := range items {
		if strings.EqualFold(i, item) {
			return true
		}
	}
	return false
}
