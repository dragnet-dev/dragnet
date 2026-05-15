package incident

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidIncident(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "npm-2026-001.yaml")

	yaml := `id: npm-2026-001
packages:
  - name: "@tanstack/react-router"
    ecosystem: npm
    affected_versions:
      - "1.169.5"
attack_type: account_takeover
severity: critical
description: "Test incident for supply chain attack via account takeover"
references:
  - https://www.wiz.io/blog/tanstack
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	inc, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if inc.ID != "npm-2026-001" {
		t.Errorf("ID = %q, want npm-2026-001", inc.ID)
	}
	if inc.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", inc.Severity)
	}
	if len(inc.Packages) != 1 {
		t.Errorf("Packages len = %d, want 1", len(inc.Packages))
	}
	if inc.Packages[0].Ecosystem != "npm" {
		t.Errorf("Ecosystem = %q, want npm", inc.Packages[0].Ecosystem)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/incident.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("{{invalid yaml[["), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}
