package wazuh_test

import (
	"encoding/xml"
	"os"
	"strings"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/backends/wazuh"
)

func goldenTest(t *testing.T, inputFile, goldenFile string) {
	t.Helper()

	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("read input %s: %v", inputFile, err)
	}

	b := wazuh.New()
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
		t.Errorf("Wazuh output mismatch for %s.\nWANT:\n%s\n\nGOT:\n%s",
			inputFile, strings.TrimSpace(string(want)), strings.TrimSpace(string(got)))
	}
}

func TestCompileNetwork(t *testing.T) {
	goldenTest(t, "testdata/input_network.sigma.yaml", "testdata/golden_network.xml")
}

func TestCompileProcess(t *testing.T) {
	goldenTest(t, "testdata/input_process.sigma.yaml", "testdata/golden_process.xml")
}

func TestCompileFileHash(t *testing.T) {
	goldenTest(t, "testdata/input_file.sigma.yaml", "testdata/golden_file.xml")
}

func TestBackendMeta(t *testing.T) {
	b := wazuh.New()
	if b.Name() != "wazuh" {
		t.Errorf("Name() = %q, want %q", b.Name(), "wazuh")
	}
	if b.OutputExtension() != ".xml" {
		t.Errorf("OutputExtension() = %q, want %q", b.OutputExtension(), ".xml")
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
	b := wazuh.New()
	got, err := b.Compile(sigma)
	if err != nil {
		t.Fatalf("Compile: unexpected error: %v", err)
	}
	// Must be valid XML
	var v interface{}
	if err := xml.Unmarshal(got, &v); err != nil {
		t.Errorf("output is not valid XML: %v\n%s", err, string(got))
	}
}

func TestXMLValidity(t *testing.T) {
	for _, f := range []string{
		"testdata/input_network.sigma.yaml",
		"testdata/input_process.sigma.yaml",
		"testdata/input_file.sigma.yaml",
	} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		b := wazuh.New()
		got, err := b.Compile(data)
		if err != nil {
			t.Fatalf("%s: Compile error: %v", f, err)
		}
		var v interface{}
		if err := xml.Unmarshal(got, &v); err != nil {
			t.Errorf("%s: invalid XML: %v\n%s", f, err, string(got))
		}
	}
}

func TestWazuhRuleIDStability(t *testing.T) {
	data, err := os.ReadFile("testdata/input_network.sigma.yaml")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	b := wazuh.New()
	out1, _ := b.Compile(data)
	out2, _ := b.Compile(data)
	if string(out1) != string(out2) {
		t.Error("rule ID not stable across two compilations of same input")
	}
}
