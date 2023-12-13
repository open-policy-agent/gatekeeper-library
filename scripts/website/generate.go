package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/utils/strings/slices"
)

const (
	// raw github source URL.
	sourceURL = "https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/"

	// directory entry point for parsing.
	entryPoint         = "library"
	mutationEntryPoint = "mutation"
	sidebarPath        = "website/sidebars.js"

	// regex patterns.
	pspReadmeLinkPattern = `\[([^\[\]]+)\]\(([^(]+)\)`
	generalPattern       = `(\s*)(type:\s+'category',\s+label:\s+'General',\s+collapsed:\s+true,\s+items:\s*\[\s)(\s*)([^\]]*,)`
	pspPattern           = `(\s*)(type:\s+'category',\s+label:\s+'Pod Security Policy',\s+collapsed:\s+true,\s+items:\s*\[\s)(\s*)([^\]]*,)`
	mutationPattern      = `(\s*)(type:\s+'category',\s+label:\s+'Mutation',\s+collapsed:\s+true,\s+items:\s*\[\s)(\s*)([^\]]*,)`
)

// Skip including examples for the following Kinds.
var skipExampleKinds = []string{"AdmissionReview"}

// Suite ...
// ToDo (nilekh): Get this struct from the Gatekeeper repo.
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
		if os.Mkdir(filepath.Join(rootDir, "website/docs/validation"), 0o755) != nil {
			fmt.Println("error while creating directory")
			panic(err)
		}
	}

	validationSidebarItems := make(map[string][]string)
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
					validationSidebarItems[entry.Name()] = append(validationSidebarItems[entry.Name()], dir.Name())
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

							exampleResource := make(map[string]interface{})
							err = yaml.Unmarshal(exampleContent, &exampleResource)
							if err != nil {
								fmt.Printf("error while unmarshaling: %v", exampleRawURL)
								panic(err)
							}

							if exampleKind, ok := exampleResource["kind"].(string); !ok {
								fmt.Printf("error while parsing kind: %v", exampleRawURL)
								panic(err)
							} else if !slices.Contains(skipExampleKinds, exampleKind) {
								examples += fmt.Sprintf("<details>\n<summary>%s</summary>\n\n```yaml\n%s\n```\n\nUsage\n\n```shell\nkubectl apply -f %s\n```\n\n</details>\n", testCase.Name, exampleContent, exampleRawURL)
							}
						}

						allExamples += fmt.Sprintf("<details>\n<summary>%s</summary>\n\n%s\n%s\n\n</details>", test.Name, constraintExample, examples)
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
						"%TITLE%", getConstraintTemplateTitle(constraintTemplate),
						"%DESCRIPTION%", getConstraintTemplateDescription(constraintTemplate),
						"%FILENAME%", dir.Name(),
					)

					err = os.WriteFile(
						filepath.Join(rootDir, "website/docs/validation", fmt.Sprintf("%s.md", dir.Name())),
						[]byte(replacer.Replace(string(templateContent))),
						0o600,
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
	mutationSidebarItems := make(map[string][]string)
	mutationPath := filepath.Join(rootDir, mutationEntryPoint)
	mutationDirEntry, err := os.ReadDir(mutationPath)
	if err != nil {
		fmt.Println("error while listing directories under mutation")
		panic(err)
	}

	// create website mutation directory if not exists
	if _, err := os.Stat(filepath.Join(rootDir, "website/docs/mutation-examples")); os.IsNotExist(err) {
		if os.Mkdir(filepath.Join(rootDir, "website/docs/mutation-examples"), 0o755) != nil {
			fmt.Println("error while creating directory")
			panic(err)
		}
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
				mutationSidebarItems[entry.Name()] = append(mutationSidebarItems[entry.Name()], dir.Name())

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
							"%EXAMPLES%", string(fileContentBytes),
							"%TITLE%", dir.Name(),
							"%FILENAME%", dir.Name(),
						)

						err := os.WriteFile(
							filepath.Join(rootDir, "website/docs/mutation-examples", fmt.Sprintf("%s.md", dir.Name())),
							[]byte(replacer.Replace(string(mutationTemplateContent))),
							0o600,
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

	// update README.md
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
		0o600,
	)
	if err != nil {
		fmt.Println("error while updating README.md")
		panic(err)
	}

	// update PSP README.md
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
	regex := regexp.MustCompile(pspReadmeLinkPattern)
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
		0o600,
	)
	if err != nil {
		fmt.Println("error while updating psp README.md")
		panic(err)
	}

	// update sidebar
	fmt.Println("Updating sidebar")
	var generalItems []string
	for _, item := range validationSidebarItems["general"] {
		generalItems = append(
			generalItems,
			fmt.Sprintf(
				"'validation/%s',",
				item,
			),
		)
	}

	var podSecurityPolicyItems []string
	podSecurityPolicyItems = append(podSecurityPolicyItems, "'pspintro',")
	for _, item := range validationSidebarItems["pod-security-policy"] {
		podSecurityPolicyItems = append(
			podSecurityPolicyItems,
			fmt.Sprintf(
				"'validation/%s',",
				item,
			),
		)
	}

	var mutationItems []string
	for _, item := range mutationSidebarItems["pod-security-policy"] {
		mutationItems = append(
			mutationItems,
			fmt.Sprintf(
				"'mutation-examples/%s',",
				item,
			),
		)
	}

	data, err := os.ReadFile(filepath.Join(rootDir, sidebarPath))
	if err != nil {
		log.Fatal(err)
	}

	// find and replace the matching content
	updatedSidebar := getRegexReplacedString(
		getRegexReplacedString(
			getRegexReplacedString(
				string(data),
				generalPattern,
				generalItems,
			),
			pspPattern,
			podSecurityPolicyItems,
		),
		mutationPattern,
		mutationItems,
	)

	// write the updated content to the file
	err = os.WriteFile(filepath.Join(rootDir, sidebarPath), []byte(updatedSidebar), 0o600)
	if err != nil {
		log.Fatal(err)
	}
}

func getRegexReplacedString(content string, pattern string, replacement []string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(content)
	if len(matches) < 5 {
		panic("Error: could not find match in file content")
	}

	// add indentation to each item
	for i, item := range replacement {
		replacement[i] = fmt.Sprintf(
			"%s%s",
			matches[3],
			item,
		)
	}

	updatedContent := fmt.Sprintf("%s%s%s",
		matches[1],
		matches[2],
		strings.Join(replacement, "\n"),
	)

	return re.ReplaceAllString(content, updatedContent)
}

// TODO: Use shared pkg.
func getConstraintTemplateMetadata(constraintTemplate map[string]interface{}) map[string]interface{} {
	metadata, ok := constraintTemplate["metadata"].(map[string]interface{})
	if !ok {
		panic("error while retrieving constraintTemplate metadata")
	}
	return metadata
}

func getConstraintTemplateAnnotations(constraintTemplate map[string]interface{}) map[string]interface{} {
	metadata := getConstraintTemplateMetadata(constraintTemplate)

	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		panic("error while retrieving constraintTemplate annotations")
	}

	return annotations
}

func getConstraintTemplateTitle(constraintTemplate map[string]interface{}) string {
	annotations := getConstraintTemplateAnnotations(constraintTemplate)

	return fmt.Sprintf("%s", annotations["metadata.gatekeeper.sh/title"])
}

func getConstraintTemplateDescription(constraintTemplate map[string]interface{}) string {
	annotations := getConstraintTemplateAnnotations(constraintTemplate)

	return fmt.Sprintf("%s", annotations["description"])
}
