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

	e.Export(inc)
	if err := e.WriteFiles(dir); err != nil {
		t.Fatalf("WriteFiles: %v", err)
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

	e.Export(inc1)
	e.Export(inc2)
	if err := e.WriteFiles(dir); err != nil {
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

func TestExportScrubsStaleDomainFeedEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "domains.txt"), []byte(strings.Join([]string{
		"Object.assign",
		"Rar.exe",
		"config.json",
		"github.com",
		"raw.githubusercontent",
		"old.evil.example",
	}, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	inc := &incident.Incident{
		ID: "malware-2026-001",
		Indicators: incident.Indicators{
			Domains: []incident.IndicatorValue{{Value: "new-bad.example.net"}},
		},
	}
	exp := New()
	exp.Export(inc)
	if err := exp.WriteFiles(dir); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "domains.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, bad := range []string{"Object.assign", "Rar.exe", "config.json", "github.com", "raw.githubusercontent", "old.evil.example"} {
		if strings.Contains(got, bad) {
			t.Fatalf("domains.txt still contains stale invalid domain %q:\n%s", bad, got)
		}
	}
	if !strings.Contains(got, "new-bad.example.net") {
		t.Fatalf("domains.txt missing new valid domain:\n%s", got)
	}
}

func TestExportScrubsStaleUnifiedDomainEntries(t *testing.T) {
	dir := t.TempDir()
	stale := []UnifiedEntry{
		{Type: "domain", Value: "Object.assign", IncidentID: "old-1"},
		{Type: "domain", Value: "github.com", IncidentID: "old-2"},
		{Type: "domain", Value: "raw.githubusercontent", IncidentID: "old-3"},
		{Type: "domain", Value: "valid.example.net", IncidentID: "old-4"},
	}
	data, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unified.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	inc := &incident.Incident{
		ID: "malware-2026-002",
		Indicators: incident.Indicators{
			Domains: []incident.IndicatorValue{{Value: "fresh.example.net"}},
		},
	}
	exp := New()
	exp.Export(inc)
	if err := exp.WriteFiles(dir); err != nil {
		t.Fatal(err)
	}

	data, err = os.ReadFile(filepath.Join(dir, "unified.json"))
	if err != nil {
		t.Fatal(err)
	}
	var entries []UnifiedEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}
	values := map[string]bool{}
	for _, entry := range entries {
		values[entry.Value] = true
	}
	for _, bad := range []string{"Object.assign", "github.com", "raw.githubusercontent"} {
		if values[bad] {
			t.Fatalf("unified.json still contains stale invalid domain %q", bad)
		}
	}
	if !values["valid.example.net"] || !values["fresh.example.net"] {
		t.Fatalf("unified.json did not keep valid domains: %#v", values)
	}
}
