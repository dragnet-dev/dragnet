package sentinel_test

import (
	"os"
	"strings"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/backends/sentinel"
)

// goldenTest reads the input Sigma YAML, compiles it with the Sentinel backend,
// and compares the output against the golden file. Set UPDATE_GOLDEN=1 to rewrite.
func goldenTest(t *testing.T, inputFile, goldenFile string) {
	t.Helper()

	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("read input %s: %v", inputFile, err)
	}

	b := sentinel.New()
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
		t.Errorf("Sentinel output mismatch for %s.\nWANT:\n%s\n\nGOT:\n%s", inputFile, wantStr, gotStr)
	}
}

func TestCompileNetwork(t *testing.T) {
	goldenTest(t,
		"testdata/input_network.sigma.yaml",
		"testdata/golden_network.yaml",
	)
}

func TestCompileProcess(t *testing.T) {
	goldenTest(t,
		"testdata/input_process.sigma.yaml",
		"testdata/golden_process.yaml",
	)
}

func TestBackendMeta(t *testing.T) {
	b := sentinel.New()
	if b.Name() != "sentinel" {
		t.Errorf("Name() = %q, want %q", b.Name(), "sentinel")
	}
	if b.OutputExtension() != ".yaml" {
		t.Errorf("OutputExtension() = %q, want %q", b.OutputExtension(), ".yaml")
	}
}

func TestSeverityMapping(t *testing.T) {
	cases := []struct {
		level   string
		wantSev string
	}{
		{"critical", "High"},
		{"high", "High"},
		{"medium", "Medium"},
		{"low", "Low"},
	}

	for _, tc := range cases {
		sigma := []byte(`title: 'Test'
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
		b := sentinel.New()
		got, err := b.Compile(sigma)
		if err != nil {
			t.Fatalf("level=%s: Compile error: %v", tc.level, err)
		}
		if !strings.Contains(string(got), "severity: "+tc.wantSev) {
			t.Errorf("level=%s: want severity %q in output:\n%s", tc.level, tc.wantSev, string(got))
		}
	}
}

func TestMITRETagMapping(t *testing.T) {
	sigma := []byte(`title: 'MITRE Test'
id: 00000000-0000-0000-0000-000000000002
status: stable
description: Test MITRE mapping
logsource:
  category: network_connection
  product: any
detection:
  selection:
    DestinationIp|contains:
      - '1.2.3.4'
  condition: selection
level: high
tags:
  - attack.t1041
  - attack.t1552
`)
	b := sentinel.New()
	got, err := b.Compile(sigma)
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}
	gotStr := string(got)
	if !strings.Contains(gotStr, "Exfiltration") {
		t.Errorf("expected Exfiltration tactic; got:\n%s", gotStr)
	}
	if !strings.Contains(gotStr, "CredentialAccess") {
		t.Errorf("expected CredentialAccess tactic; got:\n%s", gotStr)
	}
	if !strings.Contains(gotStr, "T1041") {
		t.Errorf("expected T1041 technique; got:\n%s", gotStr)
	}
	if !strings.Contains(gotStr, "T1552") {
		t.Errorf("expected T1552 technique; got:\n%s", gotStr)
	}
}

func TestConnectorMapping(t *testing.T) {
	categories := []struct {
		category  string
		wantTable string
	}{
		{"network_connection", "DeviceNetworkEvents"},
		{"file_event", "DeviceFileEvents"},
		{"process_creation", "DeviceProcessEvents"},
		{"registry_event", "DeviceRegistryEvents"},
	}

	for _, tc := range categories {
		sigma := []byte(`title: 'Connector test'
id: 00000000-0000-0000-0000-000000000003
status: stable
description: Test connector mapping
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
		b := sentinel.New()
		got, err := b.Compile(sigma)
		if err != nil {
			t.Fatalf("category=%s: Compile error: %v", tc.category, err)
		}
		if !strings.Contains(string(got), tc.wantTable) {
			t.Errorf("category=%s: want %q in output:\n%s", tc.category, tc.wantTable, string(got))
		}
	}
}
