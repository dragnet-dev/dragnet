package kql_test

import (
	"os"
	"strings"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/backends/kql"
)

// goldenTest reads the input Sigma YAML, compiles it with the KQL backend,
// and compares the output against the golden file. When the UPDATE_GOLDEN env
// var is set the golden file is rewritten instead.
func goldenTest(t *testing.T, inputFile, goldenFile string) {
	t.Helper()

	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("read input %s: %v", inputFile, err)
	}

	b := kql.New()
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

	gotStr := strings.TrimSpace(string(got))
	wantStr := strings.TrimSpace(string(want))
	if gotStr != wantStr {
		t.Errorf("KQL output mismatch for %s.\nWANT:\n%s\n\nGOT:\n%s", inputFile, wantStr, gotStr)
	}
}

func TestCompileNetwork(t *testing.T) {
	goldenTest(t,
		"testdata/input_network.sigma.yaml",
		"testdata/golden_network.kql",
	)
}

func TestCompileFileHash(t *testing.T) {
	goldenTest(t,
		"testdata/input_file.sigma.yaml",
		"testdata/golden_file.kql",
	)
}

func TestCompileProcess(t *testing.T) {
	goldenTest(t,
		"testdata/input_process.sigma.yaml",
		"testdata/golden_process.kql",
	)
}

func TestBackendMeta(t *testing.T) {
	b := kql.New()
	if b.Name() != "kql" {
		t.Errorf("Name() = %q, want %q", b.Name(), "kql")
	}
	if b.OutputExtension() != ".kql" {
		t.Errorf("OutputExtension() = %q, want %q", b.OutputExtension(), ".kql")
	}
}

func TestCompileMultiValue(t *testing.T) {
	sigma := []byte(`
title: 'Multi-value test'
id: 00000000-0000-0000-0000-000000000001
status: stable
description: Test with multiple IOC values
logsource:
  category: network_connection
  product: any
detection:
  selection:
    DestinationIp|contains:
      - '1.2.3.4'
      - '5.6.7.8'
  condition: selection
level: high
`)
	b := kql.New()
	got, err := b.Compile(sigma)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	gotStr := string(got)
	if !strings.Contains(gotStr, `has_any ("1.2.3.4", "5.6.7.8")`) {
		t.Errorf("expected has_any for multi-value; got:\n%s", gotStr)
	}
}

func TestCompileUnknownCategory(t *testing.T) {
	sigma := []byte(`
title: 'Unknown category'
id: 00000000-0000-0000-0000-000000000002
status: experimental
description: Test unknown logsource category
logsource:
  category: unknown_category
  product: any
detection:
  selection:
    CommandLine|contains:
      - 'evil'
  condition: selection
level: low
`)
	b := kql.New()
	got, err := b.Compile(sigma)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// Should fall back to DeviceEvents table
	if !strings.Contains(string(got), "DeviceEvents") {
		t.Errorf("expected DeviceEvents fallback; got:\n%s", string(got))
	}
}
