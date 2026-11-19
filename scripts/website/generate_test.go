package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateMutationMarkdown(t *testing.T) {
	samplesDir := t.TempDir()
	files := map[string]string{
		"mutation-a.yaml": "kind: Assign\nmetadata:\n  name: a\n",
		"mutation-b.yaml": "kind: ModifySet\nmetadata:\n  name: b\n",
		"README.md":       "# readme\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(samplesDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(samplesDir, "mutation-example"), 0o755); err != nil {
		t.Fatal(err)
	}

	templateContent, err := os.ReadFile("mutation-template.md")
	if err != nil {
		t.Fatal(err)
	}

	got, err := generateMutationMarkdown(string(templateContent), samplesDir, "https://example.com/samples/", "sample")
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"id: sample\n",
		"# sample\n",
		"kubectl apply -f https://example.com/samples/mutation-a.yaml\nkubectl apply -f https://example.com/samples/mutation-b.yaml\n",
		"kind: Assign\nmetadata:\n  name: a\n---\nkind: ModifySet\nmetadata:\n  name: b\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("generated markdown does not contain %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"readme", "mutation-example", "%"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("generated markdown unexpectedly contains %q:\n%s", unwanted, got)
		}
	}
}
