package chronicle_test

import (
	"os"
	"strings"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/backends/chronicle"
)

func goldenTest(t *testing.T, inputFile, goldenFile string) {
	t.Helper()

	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("read input %s: %v", inputFile, err)
	}

	b := chronicle.New()
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
		t.Errorf("Chronicle output mismatch for %s.\nWANT:\n%s\n\nGOT:\n%s",
			inputFile, strings.TrimSpace(string(want)), strings.TrimSpace(string(got)))
	}
}

func TestCompileNetwork(t *testing.T) {
	goldenTest(t, "testdata/input_network.sigma.yaml", "testdata/golden_network.yaral")
}

func TestCompileProcess(t *testing.T) {
	goldenTest(t, "testdata/input_process.sigma.yaml", "testdata/golden_process.yaral")
}

func TestCompileFileHash(t *testing.T) {
	goldenTest(t, "testdata/input_file.sigma.yaml", "testdata/golden_file.yaral")
}

func TestBackendMeta(t *testing.T) {
	b := chronicle.New()
	if b.Name() != "chronicle" {
		t.Errorf("Name() = %q, want %q", b.Name(), "chronicle")
	}
	if b.OutputExtension() != ".yaral" {
		t.Errorf("OutputExtension() = %q, want %q", b.OutputExtension(), ".yaral")
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
	b := chronicle.New()
	got, err := b.Compile(sigma)
	if err != nil {
		t.Fatalf("Compile: unexpected error: %v", err)
	}
	if len(got) == 0 {
		t.Error("expected non-empty output")
	}
}

func TestYARALStructure(t *testing.T) {
	data, _ := os.ReadFile("testdata/input_network.sigma.yaml")
	b := chronicle.New()
	got, err := b.Compile(data)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	gotStr := string(got)
	for _, required := range []string{"rule ", "meta:", "events:", "condition:"} {
		if !strings.Contains(gotStr, required) {
			t.Errorf("YARA-L output missing %q:\n%s", required, gotStr)
		}
	}
}

func TestChronicleEventType(t *testing.T) {
	cases := []struct {
		category  string
		wantEvent string
	}{
		{"network_connection", "NETWORK_CONNECTION"},
		{"file_event", "FILE_CREATION"},
		{"process_creation", "PROCESS_LAUNCH"},
	}
	for _, tc := range cases {
		sigma := []byte(`title: 'Event type test'
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
		b := chronicle.New()
		got, err := b.Compile(sigma)
		if err != nil {
			t.Fatalf("category=%s: %v", tc.category, err)
		}
		if !strings.Contains(string(got), tc.wantEvent) {
			t.Errorf("category=%s: want event type %q in output:\n%s", tc.category, tc.wantEvent, string(got))
		}
	}
}
