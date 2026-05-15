package splunk_test

import (
	"os"
	"strings"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/backends/splunk"
)

func goldenTest(t *testing.T, inputFile, goldenFile string) {
	t.Helper()

	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("read input %s: %v", inputFile, err)
	}

	b := splunk.New()
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
		t.Errorf("Splunk output mismatch for %s.\nWANT:\n%s\n\nGOT:\n%s",
			inputFile, strings.TrimSpace(string(want)), strings.TrimSpace(string(got)))
	}
}

func TestCompileNetwork(t *testing.T) {
	goldenTest(t, "testdata/input_network.sigma.yaml", "testdata/golden_network.spl")
}

func TestCompileProcess(t *testing.T) {
	goldenTest(t, "testdata/input_process.sigma.yaml", "testdata/golden_process.spl")
}

func TestCompileFileHash(t *testing.T) {
	goldenTest(t, "testdata/input_file.sigma.yaml", "testdata/golden_file.spl")
}

func TestBackendMeta(t *testing.T) {
	b := splunk.New()
	if b.Name() != "splunk" {
		t.Errorf("Name() = %q, want %q", b.Name(), "splunk")
	}
	if b.OutputExtension() != ".spl" {
		t.Errorf("OutputExtension() = %q, want %q", b.OutputExtension(), ".spl")
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
	b := splunk.New()
	got, err := b.Compile(sigma)
	if err != nil {
		t.Fatalf("Compile: unexpected error: %v", err)
	}
	if len(got) == 0 {
		t.Error("expected non-empty output for empty detection")
	}
}

func TestCompileMultiValue(t *testing.T) {
	sigma := []byte(`title: 'Multi-value test'
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
	b := splunk.New()
	got, err := b.Compile(sigma)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	gotStr := string(got)
	if !strings.Contains(gotStr, "1.2.3.4") || !strings.Contains(gotStr, "5.6.7.8") {
		t.Errorf("expected both IPs in output; got:\n%s", gotStr)
	}
}
