// Package cmd: `dragnet migrate-ids` rewrites source-prefixed incident IDs
// (urlhaus-3849105, cisa-cve202642897, ossf-xyz) to the canonical
// dragnet-{module}-{year}-{seq} format and updates every artifact that
// references them.
//
// It's the destructive cousin of `doctor`: doctor reports, migrate-ids
// rewrites. Default is dry-run so you can preview the mapping before
// touching anything. --apply flips the switch.
//
// Why this is opt-in and not part of sync: rewriting IDs is a breaking
// change for any consumer (port, dredge, buoy, scope, trawl) that has
// previously fetched an ID. The user controls when that breakage happens.
// Sync stays safe-by-default; migration is a deliberate operator action.
package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/dragnet-dev/dragnet/internal/index"
	"github.com/dragnet-dev/dragnet/internal/sigma"
	"github.com/spf13/cobra"
)

var migrateIDsCmd = &cobra.Command{
	Use:           "migrate-ids",
	Short:         "Rewrite source-prefixed incident IDs to dragnet-{module}-YYYY-NNNN canonical form",
	SilenceUsage:  true,
	RunE:          runMigrateIDs,
}

var (
	migrateRoot  string
	migrateApply bool
)

func init() {
	migrateIDsCmd.Flags().StringVar(&migrateRoot, "root", ".",
		"haul repo root (default cwd)")
	migrateIDsCmd.Flags().BoolVar(&migrateApply, "apply", false,
		"Write changes. Default is dry-run — prints the mapping and exits.")
}

// IDMapping holds the result of a migration run. Persisted to
// state/id-migration.json on --apply so a future rollback can restore the
// pre-migration IDs.
type IDMapping struct {
	GeneratedAt string            `json:"generated_at"`
	Mapping     map[string]string `json:"mapping"` // old_id -> new_id
}

func runMigrateIDs(_ *cobra.Command, _ []string) error {
	modules := []string{"supply", "malware", "ransomware", "cve", "container"}

	// Use the shared sigma registry as the allocator so migrate-ids and
	// future sync runs produce IDs from the same sequential space — no
	// duplicate seq numbers, deterministic re-runs. The registry is
	// loaded read-write here because --apply will Save() it at the end
	// of the migration.
	regPath := filepath.Join(migrateRoot, "state", "sigma-id-registry.json")
	reg, err := sigma.LoadRegistry(regPath)
	if err != nil {
		return fmt.Errorf("load registry: %w", err)
	}

	// Phase 1 — build the mapping by loading every shard and asking the
	// registry for each incident's canonical ID. AssignID is idempotent
	// (same input → same output) so dry-runs are safe even though they
	// mutate the in-memory registry — we just don't Save() unless --apply.
	mapping := map[string]string{}

	for _, mod := range modules {
		modRoot := filepath.Join(migrateRoot, mod)
		incidents, err := index.LoadAllJSONLShards(modRoot)
		if err != nil {
			log.Printf("[migrate-ids][%s] load: %v (skipping)", mod, err)
			continue
		}
		// Deterministic order — sort by current ID so re-runs produce the
		// same canonical assignment order.
		sort.Slice(incidents, func(i, j int) bool { return incidents[i].ID < incidents[j].ID })

		for _, inc := range incidents {
			if inc.ID == "" {
				continue
			}
			// Skip records already in canonical form.
			if strings.HasPrefix(inc.ID, "dragnet-") {
				continue
			}
			canonical := reg.AssignID(mod, inc.ID, parseFirstSeen(inc))
			mapping[inc.ID] = canonical
		}
		log.Printf("[migrate-ids][%s] mapped %d source-prefixed IDs", mod, countForModule(mapping, mod))
	}

	if len(mapping) == 0 {
		log.Printf("[migrate-ids] no source-prefixed IDs found — nothing to do")
		return nil
	}

	previewPath := writePreview(migrateRoot, mapping, migrateApply)
	log.Printf("[migrate-ids] mapping written to %s (%d entries)", previewPath, len(mapping))

	if !migrateApply {
		log.Printf("[migrate-ids] DRY-RUN. Re-run with --apply to rewrite artifacts.")
		log.Printf("[migrate-ids] sample mappings:")
		printed := 0
		for old, new := range mapping {
			if printed >= 5 {
				break
			}
			log.Printf("  %-50s -> %s", old, new)
			printed++
		}
		return nil
	}

	// Phase 2 — apply. Walk every artifact that may carry an incident ID
	// and rewrite. Files written via os.Rename(tmp, dst) for atomicity
	// within a single file (we don't promise cross-file atomicity — that
	// would need a per-run lockfile and is overkill for an opt-in tool).
	rewrites := 0
	for _, mod := range modules {
		modRoot := filepath.Join(migrateRoot, mod)

		// incidents/all/*.jsonl — record-level
		allDir := filepath.Join(modRoot, "incidents", "all")
		if entries, err := os.ReadDir(allDir); err == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
					continue
				}
				n, err := rewriteJSONLIncidents(filepath.Join(allDir, e.Name()), mapping)
				if err != nil {
					log.Printf("[migrate-ids][%s] rewrite %s: %v", mod, e.Name(), err)
					continue
				}
				rewrites += n
			}
		}

		// incidents/index.json — incidents[].id  +  campaigns[].incidents[]
		rewriteJSONFile(filepath.Join(modRoot, "incidents", "index.json"), mapping)
		// lookup/by-package.json — entry.id
		rewriteJSONFile(filepath.Join(modRoot, "lookup", "by-package.json"), mapping)
		// feeds/unified.json + jsonl — incidents[]
		rewriteJSONFile(filepath.Join(modRoot, "feeds", "unified.json"), mapping)
		rewriteJSONLFile(filepath.Join(modRoot, "feeds", "unified.jsonl"), mapping)
	}
	// Root-level cross-module feeds.
	rewriteJSONFile(filepath.Join(migrateRoot, "feeds", "unified.json"), mapping)
	rewriteJSONLFile(filepath.Join(migrateRoot, "feeds", "unified.jsonl"), mapping)

	// Actor profiles — LinkedIncidents[].IncidentID
	actorsDir := filepath.Join(migrateRoot, "actors", "profiles")
	if entries, err := os.ReadDir(actorsDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			rewriteJSONFile(filepath.Join(actorsDir, e.Name()), mapping)
		}
	}

	// Persist the mapping as the rollback artifact.
	finalPath := filepath.Join(migrateRoot, "state", "id-migration.json")
	if err := writeMapping(finalPath, mapping); err != nil {
		log.Printf("[migrate-ids] save final mapping: %v", err)
	} else {
		log.Printf("[migrate-ids] rollback artifact: %s", finalPath)
	}

	// Persist the registry so post-migration sync runs continue allocating
	// from the same sequential space (no duplicate seqs).
	if err := reg.Save(); err != nil {
		log.Printf("[migrate-ids] save registry: %v", err)
	}

	log.Printf("[migrate-ids] DONE. Renamed %d incident records across %d cross-references.", len(mapping), rewrites)
	return nil
}

// parseFirstSeen extracts the year-bucket timestamp from an incident's
// compromise_window. Returns zero time when absent so the registry falls
// back to time.Now(), matching the same default the sync pipeline uses.
func parseFirstSeen(inc *incident.Incident) time.Time {
	if inc.CompromiseWindow.Start == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, inc.CompromiseWindow.Start); err == nil {
		return t
	}
	return time.Time{}
}

func countForModule(mapping map[string]string, mod string) int {
	prefix := "dragnet-" + mod + "-"
	n := 0
	for _, v := range mapping {
		if strings.HasPrefix(v, prefix) {
			n++
		}
	}
	return n
}

func writePreview(root string, mapping map[string]string, apply bool) string {
	var dest string
	if apply {
		dest = filepath.Join(root, "state", "id-migration.json")
	} else {
		dest = filepath.Join(os.TempDir(), fmt.Sprintf("migrate-ids-preview-%d.json", time.Now().Unix()))
	}
	_ = writeMapping(dest, mapping)
	return dest
}

func writeMapping(path string, mapping map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	doc := IDMapping{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Mapping:     mapping,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// rewriteJSONLIncidents rewrites every record's .id field in a JSONL of
// Incident records. Returns the number of records whose ID was rewritten.
// Uses tmp+rename for atomicity per file.
func rewriteJSONLIncidents(path string, mapping map[string]string) (int, error) {
	in, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return 0, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	bw := bufio.NewWriterSize(tmp, 1<<20)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	rewritten := 0
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			// Preserve malformed lines verbatim — better to keep weird data
			// than drop it during migration.
			bw.Write(sc.Bytes())
			bw.WriteByte('\n')
			continue
		}
		if id, ok := rec["id"].(string); ok {
			if newID, mapped := mapping[id]; mapped {
				rec["id"] = newID
				// Preserve the original source-prefixed ID as legacy_id so
				// downstream consumers can still cross-reference it. Matches
				// the schema field added in v0.1.10 + the engine's behaviour
				// in assignCanonicalIDs.
				if _, hasLegacy := rec["legacy_id"]; !hasLegacy {
					rec["legacy_id"] = id
				}
				rewritten++
			}
		}
		out, _ := json.Marshal(rec)
		bw.Write(out)
		bw.WriteByte('\n')
	}
	if err := bw.Flush(); err != nil {
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return 0, err
	}
	return rewritten, nil
}

// rewriteJSONFile rewrites every string in the JSON document that matches
// a mapping key. Brute force — walks any nested structure looking for known
// IDs. Cheap enough: typical file is ~MB-scale.
func rewriteJSONFile(path string, mapping map[string]string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return
	}
	rewritten := rewriteJSONNode(doc, mapping)
	if rewritten == 0 {
		return
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, out, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmpPath, path)
}

// rewriteJSONLFile applies rewriteJSONNode line by line (jsonl, not array).
func rewriteJSONLFile(path string, mapping map[string]string) {
	in, err := os.Open(path)
	if err != nil {
		return
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	bw := bufio.NewWriterSize(tmp, 1<<20)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var rec any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			bw.Write(sc.Bytes())
			bw.WriteByte('\n')
			continue
		}
		rewriteJSONNode(rec, mapping)
		out, _ := json.Marshal(rec)
		bw.Write(out)
		bw.WriteByte('\n')
	}
	_ = bw.Flush()
	_ = tmp.Close()
	_ = os.Rename(tmpPath, path)
}

// rewriteJSONNode walks any decoded JSON value and rewrites string values
// (and string slice members) that match a mapping key. Returns the number
// of rewrites for change-detection. Recursive; OK at this depth because
// our docs are shallow.
func rewriteJSONNode(node any, mapping map[string]string) int {
	n := 0
	switch v := node.(type) {
	case map[string]any:
		for k, val := range v {
			if s, ok := val.(string); ok {
				if newID, mapped := mapping[s]; mapped {
					v[k] = newID
					n++
				}
			} else {
				n += rewriteJSONNode(val, mapping)
			}
		}
	case []any:
		for i, val := range v {
			if s, ok := val.(string); ok {
				if newID, mapped := mapping[s]; mapped {
					v[i] = newID
					n++
				}
			} else {
				n += rewriteJSONNode(val, mapping)
			}
		}
	}
	return n
}
