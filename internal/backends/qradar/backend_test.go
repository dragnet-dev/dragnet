package qradar_test

import (
	"os"
	"strings"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/backends/qradar"
)

func goldenTest(t *testing.T, inputFile, goldenFile string) {
	t.Helper()

	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("read input %s: %v", inputFile, err)
	}

	b := qradar.New()
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
		t.Errorf("QRadar output mismatch for %s.\nWANT:\n%s\n\nGOT:\n%s",
			inputFile, strings.TrimSpace(string(want)), strings.TrimSpace(string(got)))
	}
}

func TestCompileNetwork(t *testing.T) {
	goldenTest(t, "testdata/input_network.sigma.yaml", "testdata/golden_network.aql")
}

func TestCompileProcess(t *testing.T) {
	goldenTest(t, "testdata/input_process.sigma.yaml", "testdata/golden_process.aql")
}

func TestCompileFileHash(t *testing.T) {
	goldenTest(t, "testdata/input_file.sigma.yaml", "testdata/golden_file.aql")
}

func TestBackendMeta(t *testing.T) {
	b := qradar.New()
	if b.Name() != "qradar" {
		t.Errorf("Name() = %q, want %q", b.Name(), "qradar")
	}
	if b.OutputExtension() != ".aql" {
		t.Errorf("OutputExtension() = %q, want %q", b.OutputExtension(), ".aql")
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
	b := qradar.New()
	got, err := b.Compile(sigma)
	if err != nil {
		t.Fatalf("Compile: unexpected error: %v", err)
	}
	if !strings.Contains(string(got), "SELECT") {
		t.Errorf("expected SELECT in AQL output; got:\n%s", string(got))
	}
}

func TestAQLStructure(t *testing.T) {
	data, _ := os.ReadFile("testdata/input_network.sigma.yaml")
	b := qradar.New()
	got, err := b.Compile(data)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	gotStr := string(got)
	for _, required := range []string{"SELECT", "FROM events", "LAST 24 HOURS"} {
		if !strings.Contains(gotStr, required) {
			t.Errorf("AQL output missing %q:\n%s", required, gotStr)
		}
	}
}
