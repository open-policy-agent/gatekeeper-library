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

	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	gkapis "github.com/open-policy-agent/gatekeeper/v3/apis"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/cachemanager/parser"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/gator/reader"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/target"
	"k8s.io/apimachinery/pkg/runtime"
)

const syncAnnotation string = "metadata.gatekeeper.sh/requires-sync-data"

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
		tmpl, err := reader.ReadTemplate(scheme, system, path)
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

		// verify sync annotation is present and parsable by gatekeeper
		_, err = parser.ReadSyncRequirements(tmpl)
		if err != nil {
			return fmt.Errorf("template at path %q is missing valid %s annotation: %w", absolutePath, syncAnnotation, err)
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
	refClient    *constraintclient.Client
	nonRefClient *constraintclient.Client
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

func opaClient(referential bool) (*constraintclient.Client, error) {
	externs := rego.Externs()
	if referential {
		externs = rego.Externs("inventory")
	}

	driver, err := rego.New(rego.Tracing(false), externs)
	if err != nil {
		return nil, fmt.Errorf("creating driver: %w", err)
	}

	client, err := constraintclient.NewClient(constraintclient.Targets(&target.K8sValidationTarget{}), constraintclient.Driver(driver))
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	return client, nil
}
