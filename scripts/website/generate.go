package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// raw github source URL
	sourceURL = "https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/"

	// directory entry point for parsing
	entryPoint         = "library"
	mutationEntryPoint = "mutation"
)

// Suite ...
// ToDo (nilekh): Get this struct from the Gatekeeper repo
type Suite struct {
	Kind       string `yaml:"kind"`
	APIVersion string `yaml:"apiVersion"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Tests []struct {
		Name       string `yaml:"name"`
		Template   string `yaml:"template"`
		Constraint string `yaml:"constraint"`
		Cases      []struct {
			Name       string `yaml:"name"`
			Object     string `yaml:"object"`
			Assertions []struct {
				Violations string `yaml:"violations"`
			} `yaml:"assertions"`
		} `yaml:"cases"`
	} `yaml:"tests"`
}

func main() {
	pwd, err := os.Getwd()
	if err != nil {
		fmt.Println("error while getting pwd")
		panic(err)
	}

	rootDir := filepath.Join(pwd, "..", "..")
	libraryPath := filepath.Join(rootDir, entryPoint)
	dirEntry, err := os.ReadDir(libraryPath)
	if err != nil {
		fmt.Println("error while listing directories under library")
		panic(err)
	}

	// create website validation directory if not exists
	if _, err := os.Stat(filepath.Join(rootDir, "website/docs/validation")); os.IsNotExist(err) {
		os.Mkdir(filepath.Join(rootDir, "website/docs/validation"), 0755)
	}

	for _, entry := range dirEntry {
		if entry.Type().IsDir() {
			basePath, err := filepath.Abs(filepath.Join(libraryPath, entry.Name()))
			if err != nil {
				fmt.Println("error while getting absolute path for ", entry.Name())
				panic(err)
			}
			directories, err := os.ReadDir(basePath)
			if err != nil {
				fmt.Println("error while listing directories under ", entry.Name())
				panic(err)
			}

			for _, dir := range directories {
				if dir.Type().IsDir() {
					fmt.Println("Generating markdown for ", filepath.Join(basePath, dir.Name()))

					suiteContent, err := os.ReadFile(filepath.Join(basePath, dir.Name(), "suite.yaml"))
					if err != nil {
						fmt.Println("error while reading suite.yaml")
						panic(err)
					}

					suite := Suite{}
					err = yaml.Unmarshal(suiteContent, &suite)
					if err != nil {
						fmt.Println("error while unmarshaling suite.yaml")
						panic(err)
					}

					// ConstraintTemplate
					// Get raw github source URL
					constraintTemplateRawURL := sourceURL + filepath.Join(entryPoint, entry.Name(), dir.Name(), "template.yaml")
					constraintTemplateContent, err := os.ReadFile(filepath.Join(basePath, dir.Name(), "template.yaml"))
					if err != nil {
						fmt.Println("error while reading template.yaml")
						panic(err)
					}

					constraintTemplate := make(map[string]interface{})
					err = yaml.Unmarshal(constraintTemplateContent, &constraintTemplate)
					if err != nil {
						fmt.Println("error while unmarshaling template.yaml")
						panic(err)
					}

					allExamples := ""
					for _, test := range suite.Tests {
						constraintRawURL := sourceURL + filepath.Join(entryPoint, entry.Name(), dir.Name(), test.Constraint)
						constraintContent, err := os.ReadFile(filepath.Join(basePath, dir.Name(), test.Constraint))
						if err != nil {
							fmt.Println("error while reading constraint.yaml")
							panic(err)
						}
						constraintExample := fmt.Sprintf("<details>\n<summary>constraint</summary>\n\n```yaml\n%s\n```\n\nUsage\n\n```shell\nkubectl apply -f %s\n```\n\n</details>\n", constraintContent, constraintRawURL)

						examples := ""
						for _, testCase := range test.Cases {
							exampleRawURL := sourceURL + filepath.Join(entryPoint, entry.Name(), dir.Name(), testCase.Object)

							exampleContent, err := os.ReadFile(filepath.Join(basePath, dir.Name(), testCase.Object))
							if err != nil {
								fmt.Println("error while reading ", testCase.Object)
								panic(err)
							}
							examples += fmt.Sprintf("<details>\n<summary>%s</summary>\n\n```yaml\n%s\n```\n\nUsage\n\n```shell\nkubectl apply -f %s\n```\n\n</details>\n", testCase.Name, exampleContent, exampleRawURL)
						}

						allExamples += fmt.Sprintf("<details>\n<summary>%s</summary><blockquote>\n\n%s\n%s\n\n</blockquote></details>", test.Name, constraintExample, examples)
					}

					templateContent, err := os.ReadFile(filepath.Join(pwd, "template.md"))
					if err != nil {
						fmt.Println("error while reading template.md")
						panic(err)
					}

					replacer := strings.NewReplacer(
						"%TEMPLATE%", string(constraintTemplateContent),
						"%RAWURL%", constraintTemplateRawURL,
						"%EXAMPLES%", allExamples,
						"%TITLE%", fmt.Sprintf("%s", constraintTemplate["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["metadata.gatekeeper.sh/title"]),
						"%DESCRIPTION%", fmt.Sprintf("%s", constraintTemplate["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["description"]),
						"%FILENAME%", dir.Name(),
					)

					err = os.WriteFile(
						filepath.Join(rootDir, "website/docs/validation", fmt.Sprintf("%s.md", dir.Name())),
						[]byte(replacer.Replace(string(templateContent))),
						0644,
					)
					if err != nil {
						fmt.Println("error while writing file")
						panic(err)
					}
				}
			}
		}
	}

	// mutation
	mutationPath := filepath.Join(rootDir, mutationEntryPoint)
	mutationDirEntry, err := os.ReadDir(mutationPath)
	if err != nil {
		fmt.Println("error while listing directories under mutation")
		panic(err)
	}

	// create website mutation directory if not exists
	if _, err := os.Stat(filepath.Join(rootDir, "website/docs/mutation-examples")); os.IsNotExist(err) {
		os.Mkdir(filepath.Join(rootDir, "website/docs/mutation-examples"), 0755)
	}

	for _, entry := range mutationDirEntry {
		if entry.Type().IsDir() {
			basePath, err := filepath.Abs(filepath.Join(mutationPath, entry.Name()))
			if err != nil {
				fmt.Println("error while getting absolute path for ", entry.Name())
				panic(err)
			}
			directories, err := os.ReadDir(basePath)
			if err != nil {
				fmt.Println("error while listing directories under ", entry.Name())
				panic(err)
			}

			for _, dir := range directories {
				if dir.Type().IsDir() {
					fmt.Println("Generating markdown for ", filepath.Join(basePath, dir.Name()))
				}

				// get all files with name starting with "mutation"
				files, err := os.ReadDir(filepath.Join(basePath, dir.Name(), "samples"))
				if err != nil {
					panic(err)
				}

				mutationTemplateContent, err := os.ReadFile(filepath.Join(pwd, "mutation-template.md"))
				if err != nil {
					fmt.Println("error while reading mutation-template.md")
					panic(err)
				}

				for _, file := range files {
					var fileContentBytes []byte
					if strings.HasPrefix(file.Name(), "mutation") {
						// read mutation.yaml
						fileContentBytes, err = os.ReadFile(filepath.Join(basePath, dir.Name(), "samples", file.Name()))
						if err != nil {
							fmt.Println("error while reading ", file.Name())
							panic(err)
						}

						replacer := strings.NewReplacer(
							"%RAWURL%", sourceURL+filepath.Join(mutationEntryPoint, entry.Name(), dir.Name(), "samples", file.Name()),
							"%EXAMPLES%", fmt.Sprintf("%s", fileContentBytes),
							"%TITLE%", dir.Name(),
							"%FILENAME%", dir.Name(),
						)

						err := os.WriteFile(
							filepath.Join(rootDir, "website/docs/mutation-examples", fmt.Sprintf("%s.md", dir.Name())),
							[]byte(replacer.Replace(string(mutationTemplateContent))),
							0644,
						)
						if err != nil {
							fmt.Println("error while writing ", file.Name())
							panic(err)
						}
					}
				}
			}
		}
	}

	//update README.md
	fmt.Println("Updating README.md")
	readmeTemplateContent, err := os.ReadFile(filepath.Join(rootDir, "scripts/website", "readme-template.md"))
	if err != nil {
		fmt.Println("error while reading readme-template.md")
		panic(err)
	}

	readmeContent, err := os.ReadFile(filepath.Join(rootDir, "README.md"))
	if err != nil {
		fmt.Println("error while reading README.md")
		panic(err)
	}

	err = os.WriteFile(
		filepath.Join(rootDir, "website/docs/intro.md"),
		[]byte(strings.Replace(string(readmeTemplateContent), "%CONTENT%", string(readmeContent), 1)),
		0644,
	)
	if err != nil {
		fmt.Println("error while updating README.md")
		panic(err)
	}

	//update PSP README.md
	fmt.Println("Updating PSP README.md")
	pspReadmeTemplateContent, err := os.ReadFile(filepath.Join(rootDir, "scripts/website", "pspreadme-template.md"))
	if err != nil {
		fmt.Println("error while reading pspreadme-template.md")
		panic(err)
	}

	pspReadmeContent, err := os.ReadFile(filepath.Join(rootDir, "library/pod-security-policy/README.md"))
	if err != nil {
		fmt.Println("error while reading psp README.md")
		panic(err)
	}

	// find all directory path correct them to point inside validation directory
	regex := regexp.MustCompile(`\[([^\[\]]+)\]\(([^(]+)\)`)
	matches := regex.FindAllStringSubmatch(string(pspReadmeContent), -1)

	// iterate over matches and replace content within ()
	for _, match := range matches {
		// check if match does not start with http
		if !strings.HasPrefix(match[2], "http") {
			// replace content within ()
			pspReadmeContent = bytes.ReplaceAll(pspReadmeContent, []byte(fmt.Sprintf("(%s)", match[2])), []byte(fmt.Sprintf("(validation/%s)", match[2])))
		}
	}

	err = os.WriteFile(
		filepath.Join(rootDir, "website/docs/pspintro.md"),
		[]byte(strings.Replace(string(pspReadmeTemplateContent), "%CONTENT%", string(pspReadmeContent), 1)),
		0644,
	)
	if err != nil {
		fmt.Println("error while updating psp README.md")
		panic(err)
	}
}
