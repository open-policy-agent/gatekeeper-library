// Verify referential templates include sync data

package main

import (
	"context"
	"encoding/json"
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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/strings/slices"

	gkapis "github.com/open-policy-agent/gatekeeper/apis"
	"github.com/open-policy-agent/gatekeeper/pkg/gator"
	"github.com/open-policy-agent/gatekeeper/pkg/target"
)

const syncAnnotation string = "metadata.gatekeeper.sh/requiresSyncData"

var (
	pathFlag = flag.String("path", "", "Path to verify referential templates include sync data.")
	fileFlag = flag.Bool("sync-file", false, "When `true`, require a `sync.yaml` file for each referential template.")
)

var scheme *runtime.Scheme

func init() {
	scheme = runtime.NewScheme()
	err := gkapis.AddToScheme(scheme)
	if err != nil {
		panic(fmt.Errorf("adding gatekeeper apis to scheme: %w", err))
	}
}

func main() {
	flag.Parse()
	if *pathFlag == "" {
		log.Fatal("Missing `path` flag")
	}
	log.Printf("Verifying path: %s\n", *pathFlag)

	err := checkTemplates(*pathFlag)
	if err != nil {
		log.Fatal(err)
	}
}

func checkTemplates(libraryPath string) error {
	system := os.DirFS(libraryPath)

	rc, err := newRefChecker()
	if err != nil {
		return fmt.Errorf("creating referentialChecker: %w", err)
	}

	err = fs.WalkDir(system, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if d.Name() != "template.yaml" {
			return nil
		}

		// we'll use this in error messages
		absolutePath := filepath.Join(libraryPath, path)

		// read template
		tmpl, err := gator.ReadTemplate(scheme, system, path)
		if err != nil {
			return fmt.Errorf("reading template: %w", err)
		}

		// check if it's referential
		isRef, err := rc.isReferential(tmpl)
		if err != nil {
			return fmt.Errorf("detecting referential: %w", err)
		}

		// nothing to check for non referential templates
		if !isRef {
			return nil
		}

		log.Printf("Referential template: %s\n", absolutePath)

		// verify our annotation is present
		content, ok := tmpl.GetAnnotations()[syncAnnotation]
		if !ok {
			return fmt.Errorf("template at path '%s' is missing annotation with key '%s'", absolutePath, syncAnnotation)
		}

		// verify the annotation content
		if ok, err := validateRequiresSyncDataContent(strings.TrimSpace(content)); !ok {
			return fmt.Errorf("template at path '%s' annotation with key '%s': %w", absolutePath, syncAnnotation, err)
		}

		// verify that the sync object is present in the same directory as the template
		if !*fileFlag {
			return nil
		}

		syncPath := filepath.Join(filepath.Dir(path), "sync.yaml")
		_, err = fs.Stat(system, syncPath)

		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("`sync.yaml` not found in dir '%s'", filepath.Dir(absolutePath))
			}

			return fmt.Errorf("stat on '%s': %w", syncPath, err)
		}

		return nil
	})

	return err
}

type referentialChecker struct {
	refClient    *opa.Client
	nonRefClient *opa.Client
}

func newRefChecker() (*referentialChecker, error) {
	refClient, err := opaClient(true)
	if err != nil {
		return nil, fmt.Errorf("creating referential client: %w", err)
	}

	nonRefClient, err := opaClient(false)
	if err != nil {
		return nil, fmt.Errorf("creating non-referential client: %w", err)
	}

	return &referentialChecker{
		refClient:    refClient,
		nonRefClient: nonRefClient,
	}, nil
}

func (rc *referentialChecker) isReferential(ct *templates.ConstraintTemplate) (bool, error) {
	// Verify that we can add the template to a referential client.  This is a sanity
	// check for a malformed template.
	if _, err := rc.refClient.AddTemplate(context.Background(), ct); err != nil {
		return false, fmt.Errorf("adding template to referential client: %w", err)
	}

	// a referential template will fail when added to a client that does not
	// have the `inventory` field enabled.  Trying to add the template to the
	// non-referential client thus serves as an indication of it being
	// referential.
	_, err := rc.nonRefClient.AddTemplate(context.Background(), ct)
	if err == nil {
		// no error, template isn't referential
		return false, nil
	}

	// we got the specific error message that means referential
	if errTextIsReferential(err) {
		return true, nil
	}

	return false, fmt.Errorf("unrelated error when adding template to non-referential client: %w", err)
}

func errTextIsReferential(err error) bool {
	return strings.Contains(err.Error(), "check refs failed on module")
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

	client, err := opa.NewClient(opa.Targets(&target.K8sValidationTarget{}), opa.Driver(driver))
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	return client, nil
}

func validateRequiresSyncDataContent(annotation string) (bool, error) {
	allowedKeys := []string{"kinds", "groups", "versions"}

	// Remove outer quotes
	annotation = annotation[1 : len(annotation)-1]

	// Validate JSON
	if ok := json.Valid([]byte(annotation)); !ok {
		return false, fmt.Errorf("Error validating JSON format")
	}

	// Unmarshal JSON
	var contents []interface{}
	if err := json.Unmarshal([]byte(annotation), &contents); err != nil {
		return false, fmt.Errorf("Error validating JSON content")
	}

	// Validate keys
	for _, requirement := range contents {
		for _, equivalents := range requirement.([]interface{}) {
			for key := range equivalents.(map[string]interface{}) {
				if !slices.Contains(allowedKeys, key) {
					return false, fmt.Errorf("Unexpected key '%s'", key)
				}
			}
		}
	}

  return true, nil
}
