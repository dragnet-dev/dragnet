package elastic_test

import (
	"os"
	"strings"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/backends/elastic"
)

func goldenTest(t *testing.T, inputFile, goldenFile string) {
	t.Helper()

	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("read input %s: %v", inputFile, err)
	}

	b := elastic.New()
	got, err := b.Compile(inputData)
	if err != nil {
		t.Fatalf("Compile(%s): %v", inputFile, err)
	}

	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(goldenFile, got, 0644); err != nil {
			t.Fatalf("write golden %s: %v", goldenFile, err)
		}
		t.Logf("updated golden %s", goldenFile)
		return
	}

	want, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with UPDATE_GOLDEN=1 to create)", goldenFile, err)
	}

	if strings.TrimSpace(string(got)) != strings.TrimSpace(string(want)) {
		t.Errorf("Elastic output mismatch for %s.\nWANT:\n%s\n\nGOT:\n%s",
			inputFile, strings.TrimSpace(string(want)), strings.TrimSpace(string(got)))
	}
}

func TestCompileNetwork(t *testing.T) {
	goldenTest(t, "testdata/input_network.sigma.yaml", "testdata/golden_network.eql")
}

func TestCompileProcess(t *testing.T) {
	goldenTest(t, "testdata/input_process.sigma.yaml", "testdata/golden_process.eql")
}

func TestCompileFileHash(t *testing.T) {
	goldenTest(t, "testdata/input_file.sigma.yaml", "testdata/golden_file.eql")
}

func TestBackendMeta(t *testing.T) {
	b := elastic.New()
	if b.Name() != "elastic" {
		t.Errorf("Name() = %q, want %q", b.Name(), "elastic")
	}
	if b.OutputExtension() != ".eql" {
		t.Errorf("OutputExtension() = %q, want %q", b.OutputExtension(), ".eql")
	}
}

func TestCompileEmptyDetection(t *testing.T) {
	sigma := []byte(`title: 'Empty detection test'
id: 00000000-0000-0000-0000-000000000099
status: experimental
description: No detection block
logsource:
  category: network_connection
  product: any
detection:
  condition: selection
level: low
`)
	b := elastic.New()
	got, err := b.Compile(sigma)
	if err != nil {
		t.Fatalf("Compile: unexpected error: %v", err)
	}
	if len(got) == 0 {
		t.Error("expected non-empty output")
	}
}

func TestEQLEventCategory(t *testing.T) {
	cases := []struct {
		category  string
		wantEvent string
	}{
		{"network_connection", "network"},
		{"file_event", "file"},
		{"process_creation", "process"},
		{"registry_event", "registry"},
	}
	for _, tc := range cases {
		sigma := []byte(`title: 'Category test'
id: 00000000-0000-0000-0000-000000000001
status: stable
description: Test
logsource:
  category: ` + tc.category + `
  product: any
detection:
  selection:
    DestinationIp|contains:
      - '1.2.3.4'
  condition: selection
level: medium
`)
		b := elastic.New()
		got, err := b.Compile(sigma)
		if err != nil {
			t.Fatalf("category=%s: %v", tc.category, err)
		}
		if !strings.HasPrefix(strings.TrimSpace(strings.TrimLeft(string(got), "/")), tc.wantEvent) &&
			!strings.Contains(string(got), "\n"+tc.wantEvent) {
			// Check the EQL starts with the event category (after comments)
			lines := strings.Split(strings.TrimSpace(string(got)), "\n")
			found := false
			for _, l := range lines {
				if strings.HasPrefix(l, tc.wantEvent) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("category=%s: want EQL event type %q; got:\n%s", tc.category, tc.wantEvent, string(got))
			}
		}
	}
}
