package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	k8sslices "k8s.io/utils/strings/slices"
)

const (
	// raw github source URL.
	sourceURL = "https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/"

	// directory entry point for parsing.
	entryPoint           = "library"
	mutationEntryPoint   = "mutation"
	sidebarPath          = "website/sidebars.js"
	sidebarTemplatePath  = "scripts/website/sidebars-template.js"

	// regex patterns.
	pspReadmeLinkPattern = `\[([^\[\]]+)\]\(([^(]+)\)`
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
	// Track policies by bundle for bundle-based navigation
	bundleItems := make(map[string][]string)
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

					// Track bundle membership for this policy
					bundleAnnotation := getConstraintTemplateBundleAnnotation(constraintTemplate)
					if bundleAnnotation != "" {
						bundles := strings.Split(bundleAnnotation, ",")
						for _, b := range bundles {
							b = strings.TrimSpace(b)
							if b != "" {
								bundleItems[b] = append(bundleItems[b], dir.Name())
							}
						}
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
							} else if !k8sslices.Contains(skipExampleKinds, exampleKind) {
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
						"%BUNDLE%", getConstraintTemplateBundle(constraintTemplate),
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

	// update sidebar from template
	fmt.Println("Updating sidebar")
	
	// Generate General items
	generalItemsList := generateSidebarItems(validationSidebarItems["general"], "validation/", "            ")
	
	// Generate Mutation items
	mutationItemsList := generateSidebarItems(mutationSidebarItems["pod-security-policy"], "mutation-examples/", "        ")
	
	// Generate profile items for sidebar (policies organized by bundle)
	// Policies appear in every profile they belong to, since baseline and restricted
	// may require different constraint values (e.g. capabilities, seccomp).
	baselineItemsList := generateSidebarItems(bundleItems["pod-security-baseline"], "validation/", "                    ")
	restrictedItemsList := generateSidebarItems(bundleItems["pod-security-restricted"], "validation/", "                    ")

	// Collect all bundled PSP policies
	allBundledPSP := make(map[string]bool)
	for _, items := range bundleItems {
		for _, item := range items {
			allBundledPSP[item] = true
		}
	}

	// Generate "Other" PSP items: policies in pod-security-policy category without any bundle annotation
	var otherPSPItems []string
	for _, item := range validationSidebarItems["pod-security-policy"] {
		if !allBundledPSP[item] {
			otherPSPItems = append(otherPSPItems, item)
		}
	}
	otherPSPItemsList := generateSidebarItems(otherPSPItems, "validation/", "                ")

	// Read from template file
	sidebarTemplate, err := os.ReadFile(filepath.Join(rootDir, sidebarTemplatePath))
	if err != nil {
		log.Fatal(err)
	}

	// Replace all placeholders in template
	sidebarReplacer := strings.NewReplacer(
		"%GENERAL_ITEMS%", generalItemsList,
		"%MUTATION_ITEMS%", mutationItemsList,
		"%BASELINE_ITEMS%", baselineItemsList,
		"%RESTRICTED_ITEMS%", restrictedItemsList,
		"%OTHER_PSP_ITEMS%", otherPSPItemsList,
	)
	updatedSidebar := sidebarReplacer.Replace(string(sidebarTemplate))

	// write the updated content to the file
	err = os.WriteFile(filepath.Join(rootDir, sidebarPath), []byte(updatedSidebar), 0o600)
	if err != nil {
		log.Fatal(err)
	}
}

// generateSidebarItems creates a list of sidebar items with proper indentation.
func generateSidebarItems(items []string, prefix string, indent string) string {
	if len(items) == 0 {
		return ""
	}

	sort.Strings(items)

	var itemStrings []string
	for _, item := range items {
		itemStrings = append(itemStrings, fmt.Sprintf("%s'%s%s',", indent, prefix, item))
	}

	return strings.Join(itemStrings, "\n")
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

func getConstraintTemplateBundle(constraintTemplate map[string]interface{}) string {
	annotations := getConstraintTemplateAnnotations(constraintTemplate)

	bundle, ok := annotations["metadata.gatekeeper.sh/bundle"].(string)
	if !ok || bundle == "" {
		return ""
	}

	// Parse comma-separated bundles and create badges
	bundles := strings.Split(bundle, ",")
	var badges []string
	for _, b := range bundles {
		b = strings.TrimSpace(b)
		if b != "" {
			// Create a badge for each bundle
			badges = append(badges, fmt.Sprintf("`%s`", b))
		}
	}

	if len(badges) == 0 {
		return ""
	}

	return fmt.Sprintf("\n**Bundles:** %s\n", strings.Join(badges, " "))
}

func getConstraintTemplateBundleAnnotation(constraintTemplate map[string]interface{}) string {
	annotations := getConstraintTemplateAnnotations(constraintTemplate)

	bundle, ok := annotations["metadata.gatekeeper.sh/bundle"].(string)
	if !ok {
		return ""
	}
	return bundle
}
