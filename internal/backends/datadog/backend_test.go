package datadog_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/backends/datadog"
)

func goldenTest(t *testing.T, inputFile, goldenFile string) {
	t.Helper()

	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("read input %s: %v", inputFile, err)
	}

	b := datadog.New()
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
		t.Errorf("Datadog output mismatch for %s.\nWANT:\n%s\n\nGOT:\n%s",
			inputFile, strings.TrimSpace(string(want)), strings.TrimSpace(string(got)))
	}
}

func TestCompileNetwork(t *testing.T) {
	goldenTest(t, "testdata/input_network.sigma.yaml", "testdata/golden_network.json")
}

func TestCompileProcess(t *testing.T) {
	goldenTest(t, "testdata/input_process.sigma.yaml", "testdata/golden_process.json")
}

func TestCompileFileHash(t *testing.T) {
	goldenTest(t, "testdata/input_file.sigma.yaml", "testdata/golden_file.json")
}

func TestBackendMeta(t *testing.T) {
	b := datadog.New()
	if b.Name() != "datadog" {
		t.Errorf("Name() = %q, want %q", b.Name(), "datadog")
	}
	if b.OutputExtension() != ".json" {
		t.Errorf("OutputExtension() = %q, want %q", b.OutputExtension(), ".json")
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
	b := datadog.New()
	got, err := b.Compile(sigma)
	if err != nil {
		t.Fatalf("Compile: unexpected error: %v", err)
	}
	var v interface{}
	if err := json.Unmarshal(got, &v); err != nil {
		t.Errorf("output is not valid JSON: %v\n%s", err, string(got))
	}
}

func TestJSONValidity(t *testing.T) {
	for _, f := range []string{
		"testdata/input_network.sigma.yaml",
		"testdata/input_process.sigma.yaml",
		"testdata/input_file.sigma.yaml",
	} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		b := datadog.New()
		got, err := b.Compile(data)
		if err != nil {
			t.Fatalf("%s: Compile error: %v", f, err)
		}
		var v interface{}
		if err := json.Unmarshal(got, &v); err != nil {
			t.Errorf("%s: invalid JSON: %v\n%s", f, err, string(got))
		}
	}
}

func TestDatadogSeverityMapping(t *testing.T) {
	cases := []struct {
		level   string
		wantSev string
	}{
		{"critical", "critical"},
		{"high", "high"},
		{"medium", "medium"},
		{"low", "low"},
	}
	for _, tc := range cases {
		sigma := []byte(`title: 'Severity test'
id: 00000000-0000-0000-0000-000000000001
status: stable
description: Test
logsource:
  category: network_connection
  product: any
detection:
  selection:
    DestinationIp|contains:
      - '1.2.3.4'
  condition: selection
level: ` + tc.level + `
`)
		b := datadog.New()
		got, err := b.Compile(sigma)
		if err != nil {
			t.Fatalf("level=%s: %v", tc.level, err)
		}
		if !strings.Contains(string(got), `"status": "`+tc.wantSev+`"`) {
			t.Errorf("level=%s: want status %q in JSON output:\n%s", tc.level, tc.wantSev, string(got))
		}
	}
}
