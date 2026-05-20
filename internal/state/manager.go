package state

import (
	"encoding/json"
	"os"
	"time"
)

// State persists sync progress so each run resumes from where it left off.
type State struct {
	Version              int                    `json:"version"`
	LastSync             time.Time              `json:"last_sync"`
	Sources              map[string]SourceState `json:"sources"`
	ProcessedIncidentIDs []string               `json:"processed_incident_ids"`
	WazuhRuleIDCounter   int                    `json:"wazuh_rule_id_counter"`
	// Popular packages list update timestamps, keyed by ecosystem name.
	PopularPackagesLastUpdated map[string]time.Time `json:"popular_packages_last_updated,omitempty"`
	// MITRE ATT&CK bundle ETag — avoids re-downloading when unchanged (quarterly cadence).
	MITREETag string `json:"mitre_etag,omitempty"`
	// Popular container images list last refresh timestamp.
	PopularImagesLastUpdated *time.Time `json:"popular_images_last_updated,omitempty"`
}

// SourceState holds per-source resume tokens (fields vary by source type).
type SourceState struct {
	LastSync      *time.Time `json:"last_sync,omitempty"`
	ProcessedIDs  []string   `json:"processed_ids,omitempty"`
	LastCommit    string     `json:"last_commit,omitempty"`
	LastSeq       int64      `json:"last_seq,omitempty"`
	LastETag      string     `json:"last_etag,omitempty"`
	ProcessedURLs []string   `json:"processed_urls,omitempty"`
	// New registry resume tokens
	LastTimestamp       string `json:"last_timestamp,omitempty"`
	LastCommitTimestamp string `json:"last_commit_timestamp,omitempty"`
	LastUpdatedAt       string `json:"last_updated_at,omitempty"`
	LastAtomID          string `json:"last_atom_id,omitempty"`
}

// Manager loads and saves state from/to a JSON file.
type Manager struct{}

func New() *Manager { return &Manager{} }

func (m *Manager) Load(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &State{
			Version: 1,
			Sources: make(map[string]SourceState),
		}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (m *Manager) Save(path string, s *State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadImagePackages reads the image→[]packageName map from state/image_packages.json.
// Returns a nil map (no error) when the file doesn't exist yet — callers treat
// nil as "gate disabled."
func LoadImagePackages(stateDir string) (map[string][]string, error) {
	path := stateDir + "/image_packages.json"
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m map[string][]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// WriteImagePackages saves the image→[]packageName map to state/image_packages.json.
func WriteImagePackages(stateDir string, packages map[string][]string) error {
	data, err := json.MarshalIndent(packages, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(stateDir+"/image_packages.json", data, 0o644)
}

// ImagePackagesAsSet collapses an image→[]packageName map into a flat set of
// package names. Returns nil when packages is empty.
func ImagePackagesAsSet(packages map[string][]string) map[string]bool {
	if len(packages) == 0 {
		return nil
	}
	set := make(map[string]bool)
	for _, pkgs := range packages {
		for _, p := range pkgs {
			set[p] = true
		}
	}
	return set
}
