package state

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLoadMissing(t *testing.T) {
	m := New()
	s, err := m.Load(filepath.Join(t.TempDir(), "nonexistent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 1 {
		t.Errorf("default version = %d, want 1", s.Version)
	}
	if s.Sources == nil {
		t.Error("sources map should not be nil")
	}
}

func TestSaveLoad(t *testing.T) {
	m := New()
	path := filepath.Join(t.TempDir(), "state.json")

	ts := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	s := &State{
		Version:  1,
		LastSync: ts,
		Sources: map[string]SourceState{
			"osv": {ProcessedIDs: []string{"GHSA-1234"}},
		},
		ProcessedIncidentIDs: []string{"npm-2026-001"},
		WazuhRuleIDCounter:   200005,
	}

	if err := m.Save(path, s); err != nil {
		t.Fatal(err)
	}

	loaded, err := m.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if !loaded.LastSync.Equal(ts) {
		t.Errorf("LastSync = %v, want %v", loaded.LastSync, ts)
	}
	if len(loaded.ProcessedIncidentIDs) != 1 || loaded.ProcessedIncidentIDs[0] != "npm-2026-001" {
		t.Errorf("ProcessedIncidentIDs = %v", loaded.ProcessedIncidentIDs)
	}
	if loaded.WazuhRuleIDCounter != 200005 {
		t.Errorf("WazuhRuleIDCounter = %d, want 200005", loaded.WazuhRuleIDCounter)
	}
	if len(loaded.Sources["osv"].ProcessedIDs) != 1 {
		t.Errorf("osv processed IDs = %v", loaded.Sources["osv"].ProcessedIDs)
	}
}
