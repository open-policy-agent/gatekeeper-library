// Verify referential templates include sync data

package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	opa "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/gatekeeper/pkg/target"
	"gopkg.in/yaml.v3"
)

const syncAnnotation string = "metadata.gatekeeper.sh/requiresSyncData"

var (
	pathFlag = flag.String("path", "", "Path to verify referential templates include sync data.")
	fileFlag = flag.Bool("sync_file", false, "When `true`, require a `sync.yaml` file for each referential template.")
)

func main() {
	flag.Parse()
	if *pathFlag == "" {
		log.Fatal("Missing `path` flag")
	}
	log.Println("Verifying path:", *pathFlag)

	err := checkTemplates(*pathFlag)
	if err != nil {
		log.Fatal(err)
	}
}

func checkTemplates(libraryPath string) error {
	err := filepath.WalkDir(libraryPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}

		_, error := os.Stat(filepath.Join(path, "template.yaml"))
		if !os.IsNotExist(error) {
			// Unmarshall template
			krm, err := unMarshall(filepath.Join(path, "template.yaml"))
			if err != nil {
				return err
			}

			// Check if Template is Referential
			isRef, err := isReferential(krm.ConstraintTemplate)
			if err != nil {
				return fmt.Errorf("detecting referential: %w", err)
			}
			if isRef {
				// Get template name
				templateName, err := getTemplateName(krm.ConstraintTemplate)
				if err != nil {
					return err
				}
				log.Println(fmt.Errorf("Found Referential Template: %s", templateName))

				// Check if annotation is present
				hasAnno, err := hasAnnotation(krm.Metadata.Annotations, syncAnnotation)
				if err != nil {
					return err
				}
				if !hasAnno {
					return fmt.Errorf("Error: `%s` annotation not found for %s", syncAnnotation, templateName)
				}

				// Check sync.yaml is present
				_, err = os.Stat(filepath.Join(path, "sync.yaml"))
				if os.IsNotExist(err) && *fileFlag {
					return fmt.Errorf("Error: `sync.yaml` not found for %s", templateName)
				}
			}
		}

		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

type KRM struct {
	ConstraintTemplate *templates.ConstraintTemplate
	// TODO: Annotations are not queryable in templates.ConstraintTemplate/ObjectMeta
	Metadata struct {
		Annotations map[string]string `json:"annotations,omitempty"`
	} `json:"metadata,omitempty"`
}

func unMarshall(templatePath string) (*KRM, error) {
	// read the template into memory
	var ct *KRM
	f, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	err = yaml.Unmarshal(f, &ct)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling Annotations: %w", err)
	}
	err = yaml.Unmarshal(f, &ct.ConstraintTemplate)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling ConstraintTemplate: %w", err)
	}
	return ct, nil
}

func hasAnnotation(annotations map[string]string, annotation string) (bool, error) {
	if _, exists := annotations[annotation]; exists {
		return true, nil
	}
	return false, nil
}

func getTemplateName(ct *templates.ConstraintTemplate) (string, error) {
	return ct.Spec.CRD.Spec.Names.Kind, nil
}

func isReferential(ct *templates.ConstraintTemplate) (bool, error) {
	ct.SetName(strings.ToLower(ct.Spec.CRD.Spec.Names.Kind))

	nonRefClient, err := opaClient(false)
	if err != nil {
		return false, err
	}

	// a referential template will fail when added to a client that does not
	// have the `inventory` field enabled.  Trying to add the template to the
	// non-referential client thus serves as an indication of it being
	// referential.
	_, err = nonRefClient.AddTemplate(context.Background(), ct)
	if err == nil {
		// successfully added template to non-referential client.  Template is
		// non-referential.
		return false, nil
	} else if strings.Contains(err.Error(), "check refs failed on module") {
		// referential data is required.  i.e. we have a referential template

		// do a sanity check that we can add the template to a referential
		// client
		refClient, err := opaClient(true)
		if err != nil {
			return false, err
		}
		if _, err := refClient.AddTemplate(context.Background(), ct); err != nil {
			return false, fmt.Errorf("adding template to referential client: %w", err)
		}
		return true, nil
	} else {
		return false, fmt.Errorf("adding template to client: %v", err)
	}
}

func opaClient(referential bool) (*opa.Client, error) {
	externs := local.Externs()
	if referential {
		externs = local.Externs("inventory")
	}

	driver, err := local.New(local.Tracing(false), externs)
	if err != nil {
		return nil, fmt.Errorf("creating driver: %w", err)
	}

	if referential {
		driver, err = local.New(local.Tracing(false), local.Externs("inventory"))
	}
	if err != nil {
		return nil, fmt.Errorf("creating driver: %w", err)
	}

	client, err := opa.NewClient(opa.Targets(&target.K8sValidationTarget{}), opa.Driver(driver))
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	return client, nil
}
