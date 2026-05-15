package ioc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

func TestExport(t *testing.T) {
	dir := t.TempDir()
	e := New()

	inc := &incident.Incident{
		ID: "npm-2026-001",
		Indicators: incident.Indicators{
			Domains: []incident.IndicatorValue{
				{Value: "evil.example.com", Sources: []string{"wiz"}, Confidence: 0.90},
			},
			IPs: []incident.IndicatorValue{
				{Value: "1.2.3.4", Sources: []string{"wiz"}, Confidence: 0.90},
			},
			FileHashes: []incident.FileHash{
				{Algorithm: "sha256", Value: "ab4fcadaec1d282b900de5abb5b1d55dbd0e7af9628f6e7a5e2cb0e68b3b56aa", Sources: []string{"wiz"}, Confidence: 0.90},
			},
		},
	}

	if err := e.Export(inc, dir); err != nil {
		t.Fatalf("Export: %v", err)
	}

	checkFile := func(name, expected string) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			return
		}
		if !strings.Contains(string(data), expected) {
			t.Errorf("%s does not contain %q\ngot: %s", name, expected, data)
		}
	}

	checkFile("domains.txt", "evil.example.com")
	checkFile("ips.txt", "1.2.3.4")
	checkFile("sha256.txt", "ab4fcadaec1d282b900de5abb5b1d55dbd0e7af9628f6e7a5e2cb0e68b3b56aa")

	// Check unified JSON
	data, _ := os.ReadFile(filepath.Join(dir, "unified.json"))
	var entries []UnifiedEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("parse unified.json: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("unified.json has %d entries, want 3", len(entries))
	}
}

func TestExportDedup(t *testing.T) {
	dir := t.TempDir()
	e := New()

	inc1 := &incident.Incident{
		ID: "npm-2026-001",
		Indicators: incident.Indicators{
			Domains: []incident.IndicatorValue{{Value: "evil.example.com", Sources: []string{"wiz"}}},
		},
	}
	inc2 := &incident.Incident{
		ID: "npm-2026-001b",
		Indicators: incident.Indicators{
			Domains: []incident.IndicatorValue{{Value: "evil.example.com", Sources: []string{"socket"}}},
		},
	}

	if err := e.Export(inc1, dir); err != nil {
		t.Fatal(err)
	}
	if err := e.Export(inc2, dir); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "domains.txt"))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	count := 0
	for _, l := range lines {
		if l == "evil.example.com" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("domain appears %d times, want 1 (dedup failed)", count)
	}
}
