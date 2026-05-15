package suricata_test

import (
	"os"
	"strings"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/backends/suricata"
)

func goldenTest(t *testing.T, inputFile, goldenFile string) {
	t.Helper()

	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("read input %s: %v", inputFile, err)
	}

	b := suricata.New()
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
		t.Errorf("Suricata output mismatch for %s.\nWANT:\n%s\n\nGOT:\n%s",
			inputFile, strings.TrimSpace(string(want)), strings.TrimSpace(string(got)))
	}
}

func TestCompileNetwork(t *testing.T) {
	goldenTest(t, "testdata/input_network.sigma.yaml", "testdata/golden_network.rules")
}

func TestCompileProcess(t *testing.T) {
	goldenTest(t, "testdata/input_process.sigma.yaml", "testdata/golden_process.rules")
}

func TestCompileFileHash(t *testing.T) {
	goldenTest(t, "testdata/input_file.sigma.yaml", "testdata/golden_file.rules")
}

func TestBackendMeta(t *testing.T) {
	b := suricata.New()
	if b.Name() != "suricata" {
		t.Errorf("Name() = %q, want %q", b.Name(), "suricata")
	}
	if b.OutputExtension() != ".rules" {
		t.Errorf("OutputExtension() = %q, want %q", b.OutputExtension(), ".rules")
	}
}

func TestNetworkRuleHasAlertKeyword(t *testing.T) {
	data, _ := os.ReadFile("testdata/input_network.sigma.yaml")
	b := suricata.New()
	got, err := b.Compile(data)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !strings.Contains(string(got), "alert dns") && !strings.Contains(string(got), "alert ip") {
		t.Errorf("expected 'alert dns' or 'alert ip' in network rule output:\n%s", string(got))
	}
}

func TestNonNetworkEmitsPlaceholder(t *testing.T) {
	data, _ := os.ReadFile("testdata/input_process.sigma.yaml")
	b := suricata.New()
	got, err := b.Compile(data)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	gotStr := string(got)
	// Process rules produce a comment placeholder, not an alert rule
	if strings.Contains(gotStr, "alert ") {
		t.Errorf("process rule should emit placeholder, not alert rule:\n%s", gotStr)
	}
	if !strings.Contains(gotStr, "#") {
		t.Errorf("expected comment placeholder in non-network output:\n%s", gotStr)
	}
}

func TestSIDStability(t *testing.T) {
	data, _ := os.ReadFile("testdata/input_network.sigma.yaml")
	b := suricata.New()
	out1, _ := b.Compile(data)
	out2, _ := b.Compile(data)
	if string(out1) != string(out2) {
		t.Error("SID not stable across two compilations of same input")
	}
}
