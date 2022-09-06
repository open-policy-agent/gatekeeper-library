package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
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
	libraryPath := filepath.Join(rootDir, "library")
	dirEntry, err := os.ReadDir(libraryPath)
	if err != nil {
		fmt.Println("error while listing directories under library")
		panic(err)
	}

	for _, entry := range dirEntry {
		if entry.Type().IsDir() {
			basePath, _ := filepath.Abs(filepath.Join(libraryPath, entry.Name()))
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
					yaml.Unmarshal(suiteContent, &suite)

					// ConstraintTemplate
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
						constraintContent, err := os.ReadFile(filepath.Join(basePath, dir.Name(), test.Constraint))
						if err != nil {
							fmt.Println("error while reading constraint.yaml")
							panic(err)
						}
						constraintExample := fmt.Sprintf("<details>\n<summary>constraint</summary>\n\n```yaml\n%s\n```\n\n</details>\n", constraintContent)

						examples := ""
						for _, testCase := range test.Cases {
							exampleContent, err := os.ReadFile(filepath.Join(basePath, dir.Name(), testCase.Object))
							if err != nil {
								fmt.Println("error while reading ", testCase.Object)
								panic(err)
							}
							examples += fmt.Sprintf("<details>\n<summary>%s</summary>\n\n```yaml\n%s\n```\n\n</details>\n", testCase.Name, exampleContent)
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
						"%EXAMPLES%", allExamples,
						"%TITLE%", fmt.Sprintf("%s", constraintTemplate["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["metadata.gatekeeper.sh/title"]),
						"%DESCRIPTION%", fmt.Sprintf("%s", constraintTemplate["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["description"]),
						"%FILENAME%", dir.Name(),
					)

					os.WriteFile(
						filepath.Join(rootDir, "website/docs", fmt.Sprintf("%s.md", dir.Name())),
						[]byte(replacer.Replace(string(templateContent))),
						0644,
					)
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
