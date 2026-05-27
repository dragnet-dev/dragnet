package index

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

// SearchRecord is a flattened per-incident projection emitted into
// feeds/search-{module}.jsonl for port's search route. Field set is small
// on purpose — port reads the full incident from all/*.jsonl shards when
// the user clicks a result.
type SearchRecord struct {
	ID         string          `json:"id"`
	Module     string          `json:"module"`
	Summary    string          `json:"summary,omitempty"`
	Severity   string          `json:"severity,omitempty"`
	Published  string          `json:"published,omitempty"`
	Ecosystems []string        `json:"ecosystems,omitempty"`
	Tags       []string        `json:"tags,omitempty"`
	Actors     []string        `json:"actors,omitempty"`
	Packages   []SearchPackage `json:"packages,omitempty"`
	CVEIDs     []string        `json:"cve_ids,omitempty"`
}

// SearchPackage is the ecosystem/name pair carried in SearchRecord.Packages.
type SearchPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// WriteSearchIndex emits one feeds/search-{module}.jsonl file per module.
//
// Per-module sharding (vs one combined file) keeps each artifact under
// GitHub's 50 MB warning even at full bulk — a single combined file would
// hit ~90 MB once Trivy CVE records are included. Per-module files are also
// what port wants to fetch: search routes are usually module-scoped.
//
// Container records with ContainerExt.Tier == 4 (informational, the bulk
// Trivy DB without a popular-images snapshot) are excluded — including all
// 158k would dwarf the actionable Tier 1/2/3 set.
func WriteSearchIndex(allModules map[string][]*incident.Incident, rootDir string) error {
	dir := filepath.Join(rootDir, "feeds")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir feeds: %w", err)
	}

	// Wipe stale per-module files first so a renamed/dropped module doesn't
	// leave an orphan jsonl behind.
	if entries, _ := os.ReadDir(dir); len(entries) > 0 {
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, "search-") && strings.HasSuffix(name, ".jsonl") {
				_ = os.Remove(filepath.Join(dir, name))
			}
		}
	}

	// Deterministic module-iteration order so re-runs over identical input
	// produce identical files.
	moduleNames := make([]string, 0, len(allModules))
	for m := range allModules {
		moduleNames = append(moduleNames, m)
	}
	sort.Strings(moduleNames)

	for _, module := range moduleNames {
		records := buildSearchRecords(module, allModules[module])
		if len(records) == 0 {
			continue
		}
		// Sort: most-recent first, ties broken by ID for determinism.
		sort.Slice(records, func(i, j int) bool {
			if records[i].Published != records[j].Published {
				return records[i].Published > records[j].Published
			}
			return records[i].ID < records[j].ID
		})

		if err := writeSearchShards(dir, module, records); err != nil {
			return fmt.Errorf("write search-%s: %w", module, err)
		}
	}
	return nil
}

func buildSearchRecords(module string, incidents []*incident.Incident) []SearchRecord {
	out := make([]SearchRecord, 0, len(incidents))
	for _, inc := range incidents {
		if inc.ContainerExt != nil && inc.ContainerExt.Tier == 4 {
			continue
		}
		out = append(out, projectToSearch(module, inc))
	}
	return out
}

func projectToSearch(module string, inc *incident.Incident) SearchRecord {
	// Summary tuned to keep search-supply.jsonl under GitHub's 50 MB warning
	// at 234k records. 150 chars × ~230k = ~35 MB before other fields. Title
	// is redundant with the first sentence of Summary; we drop it.
	rec := SearchRecord{
		ID:        inc.ID,
		Module:    module,
		Severity:  inc.Severity,
		Published: inc.CompromiseWindow.Start,
		Summary:   truncate(inc.Description, 150),
		Actors:    inc.ActorIDs,
	}
	if inc.AttackType != "" {
		rec.Tags = append(rec.Tags, inc.AttackType)
	}
	if inc.MalwareExt != nil && inc.MalwareExt.MalwareFamily != "" {
		rec.Tags = append(rec.Tags, "malware:"+strings.ToLower(inc.MalwareExt.MalwareFamily))
	}
	if inc.RansomwareExt != nil {
		if inc.RansomwareExt.RansomwareGroup != "" {
			rec.Tags = append(rec.Tags, "ransomware:"+strings.ToLower(inc.RansomwareExt.RansomwareGroup))
		}
		for _, c := range inc.RansomwareExt.TargetedCountries {
			if c != "" {
				rec.Tags = append(rec.Tags, "country:"+strings.ToLower(c))
			}
		}
		for _, s := range inc.RansomwareExt.TargetedSectors {
			if s != "" {
				rec.Tags = append(rec.Tags, "sector:"+strings.ToLower(s))
			}
		}
	}
	if inc.CVEExt != nil && inc.CVEExt.CVEID != "" {
		rec.CVEIDs = append(rec.CVEIDs, inc.CVEExt.CVEID)
	}
	ecoSeen := map[string]bool{}
	for _, p := range inc.Packages {
		if p.Name == "" || p.Ecosystem == "" {
			continue
		}
		rec.Packages = append(rec.Packages, SearchPackage{Ecosystem: p.Ecosystem, Name: p.Name})
		if !ecoSeen[p.Ecosystem] {
			ecoSeen[p.Ecosystem] = true
			rec.Ecosystems = append(rec.Ecosystems, p.Ecosystem)
		}
	}
	return rec
}

func firstLine(s string) string {
	if s == "" {
		return ""
	}
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return strings.TrimSpace(s[:idx])
	}
	if len(s) > 120 {
		return strings.TrimSpace(s[:120])
	}
	return strings.TrimSpace(s)
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// maxSearchShardBytes keeps each search-{module}[-N].jsonl under GitHub's
// 50 MB warning. Supply's 234k records run ~54 MB unsharded; this caps any
// single file at ~45 MB and rolls over into search-supply-0.jsonl,
// search-supply-1.jsonl, etc. when needed.
const maxSearchShardBytes = 45 * 1024 * 1024

func writeSearchShards(dir, module string, recs []SearchRecord) error {
	if len(recs) == 0 {
		return nil
	}
	// Streaming encoder: open a fresh file when we'd cross the budget.
	subIdx := 0
	var f *os.File
	var enc *json.Encoder
	subBytes := 0
	openSub := func() error {
		var name string
		if subIdx == 0 {
			name = "search-" + module + ".jsonl"
		} else {
			// First overflow: rename the no-suffix file to -0 so naming stays
			// consistent across sharded modules.
			if subIdx == 1 {
				oldP := filepath.Join(dir, "search-"+module+".jsonl")
				newP := filepath.Join(dir, "search-"+module+"-0.jsonl")
				_ = os.Rename(oldP, newP)
			}
			name = fmt.Sprintf("search-%s-%d.jsonl", module, subIdx)
		}
		var err error
		f, err = os.Create(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		enc = json.NewEncoder(f)
		subBytes = 0
		return nil
	}
	if err := openSub(); err != nil {
		return err
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()
	for i := range recs {
		// Estimate this record's serialised size to decide whether to roll.
		data, err := json.Marshal(recs[i])
		if err != nil {
			continue
		}
		if subBytes > 0 && subBytes+len(data)+1 > maxSearchShardBytes {
			_ = f.Close()
			subIdx++
			if err := openSub(); err != nil {
				return err
			}
		}
		if err := enc.Encode(recs[i]); err != nil {
			return err
		}
		subBytes += len(data) + 1
	}
	return f.Close()
}
