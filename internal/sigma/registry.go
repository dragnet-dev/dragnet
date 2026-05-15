package sigma

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Registry assigns and persists sequential Dragnet IDs for sigma rules.
// IDs are stable across re-syncs: the same source incident ID always maps
// to the same Dragnet ID.
//
// Format: dragnet-<module>-<year>-<NNNN>
// Example: dragnet-supply-2026-0001
type Registry struct {
	mu   sync.Mutex
	path string
	data registryFile
}

type registryFile struct {
	Modules map[string]*moduleData `json:"modules"`
}

type moduleData struct {
	Years map[string]*yearData `json:"years"`
}

type yearData struct {
	Counter int               `json:"counter"`
	Entries map[string]string `json:"entries"` // sourceIncidentID → dragnetID
}

// LoadRegistry reads a registry from path, creating a fresh empty one if the
// file does not exist yet.
func LoadRegistry(path string) (*Registry, error) {
	r := &Registry{
		path: path,
		data: registryFile{Modules: make(map[string]*moduleData)},
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("reading registry %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &r.data); err != nil {
		return nil, fmt.Errorf("parsing registry %s: %w", path, err)
	}
	if r.data.Modules == nil {
		r.data.Modules = make(map[string]*moduleData)
	}
	return r, nil
}

// AssignID returns the Dragnet ID for a source incident, assigning a new
// sequential ID if this source incident has not been seen before.
// firstSeen determines the year bucket; uses current year if zero.
func (r *Registry) AssignID(module, sourceID string, firstSeen time.Time) string {
	year := time.Now().Format("2006")
	if !firstSeen.IsZero() {
		year = firstSeen.Format("2006")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	mod := r.data.Modules[module]
	if mod == nil {
		mod = &moduleData{Years: make(map[string]*yearData)}
		r.data.Modules[module] = mod
	}
	yr := mod.Years[year]
	if yr == nil {
		yr = &yearData{Entries: make(map[string]string)}
		mod.Years[year] = yr
	}
	if id, ok := yr.Entries[sourceID]; ok {
		return id
	}
	yr.Counter++
	id := fmt.Sprintf("dragnet-%s-%s-%04d", module, year, yr.Counter)
	yr.Entries[sourceID] = id
	return id
}

// Save merges the in-memory registry state into whatever is currently on disk
// and writes the result. Merging on every save means concurrent module syncs
// (run as separate processes) don't silently overwrite each other's entries.
func (r *Registry) Save() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Read the current on-disk state so we can layer our changes on top.
	disk := registryFile{Modules: make(map[string]*moduleData)}
	if raw, err := os.ReadFile(r.path); err == nil {
		_ = json.Unmarshal(raw, &disk)
	}
	if disk.Modules == nil {
		disk.Modules = make(map[string]*moduleData)
	}

	for modName, mod := range r.data.Modules {
		diskMod := disk.Modules[modName]
		if diskMod == nil {
			diskMod = &moduleData{Years: make(map[string]*yearData)}
			disk.Modules[modName] = diskMod
		}
		if diskMod.Years == nil {
			diskMod.Years = make(map[string]*yearData)
		}
		for yearStr, yr := range mod.Years {
			diskYr := diskMod.Years[yearStr]
			if diskYr == nil {
				diskYr = &yearData{Entries: make(map[string]string)}
				diskMod.Years[yearStr] = diskYr
			}
			if diskYr.Entries == nil {
				diskYr.Entries = make(map[string]string)
			}
			for srcID, dragnetID := range yr.Entries {
				diskYr.Entries[srcID] = dragnetID
			}
			if yr.Counter > diskYr.Counter {
				diskYr.Counter = yr.Counter
			}
		}
	}

	raw, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling registry: %w", err)
	}
	if err := os.WriteFile(r.path, append(raw, '\n'), 0o644); err != nil {
		return fmt.Errorf("writing registry %s: %w", r.path, err)
	}
	return nil
}
