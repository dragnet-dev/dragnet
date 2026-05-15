package crowdstrike_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/backends/crowdstrike"
)

// ---- LogScale golden tests ----

func goldenTestLogScale(t *testing.T, inputFile, goldenFile string) {
	t.Helper()

	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("read input %s: %v", inputFile, err)
	}

	b := crowdstrike.NewLogScale()
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
		t.Errorf("LogScale output mismatch for %s.\nWANT:\n%s\n\nGOT:\n%s",
			inputFile, strings.TrimSpace(string(want)), strings.TrimSpace(string(got)))
	}
}

func TestLogScaleCompileNetwork(t *testing.T) {
	goldenTestLogScale(t, "testdata/input_network.sigma.yaml", "testdata/golden_logscale_network.lqs")
}

func TestLogScaleCompileProcess(t *testing.T) {
	goldenTestLogScale(t, "testdata/input_process.sigma.yaml", "testdata/golden_logscale_process.lqs")
}

func TestLogScaleCompileFileHash(t *testing.T) {
	goldenTestLogScale(t, "testdata/input_file.sigma.yaml", "testdata/golden_logscale_file.lqs")
}

func TestLogScaleBackendMeta(t *testing.T) {
	b := crowdstrike.NewLogScale()
	if b.Name() != "crowdstrike-logscale" {
		t.Errorf("Name() = %q, want %q", b.Name(), "crowdstrike-logscale")
	}
	if b.OutputExtension() != ".lqs" {
		t.Errorf("OutputExtension() = %q, want %q", b.OutputExtension(), ".lqs")
	}
}

func TestLogScaleCompileEmptyDetection(t *testing.T) {
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
	b := crowdstrike.NewLogScale()
	got, err := b.Compile(sigma)
	if err != nil {
		t.Fatalf("Compile: unexpected error: %v", err)
	}
	if len(got) == 0 {
		t.Error("expected non-empty output")
	}
}

// ---- IOC golden tests ----

func goldenTestIOC(t *testing.T, inputFile, goldenFile string) {
	t.Helper()

	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("read input %s: %v", inputFile, err)
	}

	b := crowdstrike.NewIOC("detect")
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
		t.Errorf("IOC output mismatch for %s.\nWANT:\n%s\n\nGOT:\n%s",
			inputFile, strings.TrimSpace(string(want)), strings.TrimSpace(string(got)))
	}
}

func TestIOCCompileNetwork(t *testing.T) {
	goldenTestIOC(t, "testdata/input_network.sigma.yaml", "testdata/golden_ioc_network.json")
}

func TestIOCCompileFileHash(t *testing.T) {
	goldenTestIOC(t, "testdata/input_file.sigma.yaml", "testdata/golden_ioc_file.json")
}

func TestIOCBackendMeta(t *testing.T) {
	b := crowdstrike.NewIOC("detect")
	if b.Name() != "crowdstrike-ioc" {
		t.Errorf("Name() = %q, want %q", b.Name(), "crowdstrike-ioc")
	}
	if b.OutputExtension() != ".json" {
		t.Errorf("OutputExtension() = %q, want %q", b.OutputExtension(), ".json")
	}
}

func TestIOCActionDefault(t *testing.T) {
	// Empty action should default to "detect"
	b := crowdstrike.NewIOC("")
	data, _ := os.ReadFile("testdata/input_network.sigma.yaml")
	got, err := b.Compile(data)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !strings.Contains(string(got), `"action": "detect"`) {
		t.Errorf("expected action=detect as default; got:\n%s", string(got))
	}
}

func TestIOCHuntingEmpty(t *testing.T) {
	// A process/behavioural rule has no extractable IOCs → should return []
	data, _ := os.ReadFile("testdata/input_process.sigma.yaml")
	b := crowdstrike.NewIOC("detect")
	got, err := b.Compile(data)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// Must be valid JSON
	var v interface{}
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, string(got))
	}
	arr, ok := v.([]interface{})
	if !ok {
		t.Fatalf("expected JSON array; got %T", v)
	}
	if len(arr) != 0 {
		t.Errorf("expected empty array for process rule; got %d entries", len(arr))
	}
}

func TestIOCJSONValidity(t *testing.T) {
	for _, f := range []string{
		"testdata/input_network.sigma.yaml",
		"testdata/input_process.sigma.yaml",
		"testdata/input_file.sigma.yaml",
	} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		b := crowdstrike.NewIOC("detect")
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

func TestIOCNetworkExtractsIndicators(t *testing.T) {
	data, _ := os.ReadFile("testdata/input_network.sigma.yaml")
	b := crowdstrike.NewIOC("detect")
	got, err := b.Compile(data)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	gotStr := string(got)
	if !strings.Contains(gotStr, "domain") && !strings.Contains(gotStr, "ipv4") {
		t.Errorf("network rule should produce domain or ipv4 IOCs; got:\n%s", gotStr)
	}
}
