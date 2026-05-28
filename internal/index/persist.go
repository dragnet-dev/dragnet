// Package index also owns the Path-2 persistence artefacts that make haul a
// proper data hub for port/buoy/scope/trawl:
//
//   {module}/incidents/all/{shard}.jsonl  -- every merged Incident (full record),
//                                            sharded by ID prefix so no single
//                                            file exceeds GitHub's 100 MB limit.
//   {module}/incidents/index.json         -- a curated subset (recent + severe +
//                                            actor-linked) used by port's main
//                                            listing. Capped so port can load it
//                                            quickly without paginating.
//   {module}/lookup/by-package.json       -- ecosystem/name -> brief incident
//                                            metadata, used by buoy/scope/trawl
//                                            for O(1) package -> incidents lookup.
package index

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

// CuratedCapFor returns 0 for all modules — no size cap. Each backend format
// is distributed via its own satellite repo (haul-rules-sigma, haul-rules-kql,
// etc.) so repo size is bounded per-format, not per-module ceiling.
func CuratedCapFor(_ string) int {
	return 0
}

// curatedRecentWindow is the rolling window over which all incidents are kept
// regardless of severity / actor link.
const CuratedRecentWindow = 90 * 24 * time.Hour

// maxShardBytes caps the per-shard jsonl size to stay under GitHub's 50 MB
// soft-warning threshold (hard limit is 100 MB). Size-based sharding handles
// the wide variance in record size — npm advisories are ~1 KB each, but a
// single Trivy CVE that affects 30+ OS-version tuples runs to ~3 KB. Without
// size-based capping, a Trivy shard of 40k records hits ~100 MB and triggers
// GitHub's reject path.
const maxShardBytes = 45 * 1024 * 1024 // 45 MB, leaves headroom under 50 MB warning

// WriteAllJSONLShards writes every incident in `incidents` to
// {outputDir}/incidents/v1/all/{shard}.jsonl, sharded by ID prefix so each
// file stays well under git's practical size limits. A relative symlink
// incidents/all → v1/all is created for backward compatibility.
func WriteAllJSONLShards(incidents []*incident.Incident, outputDir string) error {
	dir := filepath.Join(outputDir, "incidents", "v1", "all")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir v1/all/: %w", err)
	}

	// Sort by ID once so shard contents are deterministic across runs even
	// though MergeAll's union-find iteration is map-based and gives a random
	// upstream order. Without this, every sync produces a byte-different
	// shard file (same content, different line ordering) — git treats it as
	// a diff every time, ballooning the commit + push.
	sort.Slice(incidents, func(i, j int) bool { return incidents[i].ID < incidents[j].ID })

	// Bucket by shard key, then write each bucket as one .jsonl file.
	// Bucket-key iteration order doesn't matter — each shard is its own
	// file and we sort the incidents inside each shard by their (already
	// sorted) input order.
	buckets := map[string][]*incident.Incident{}
	for _, inc := range incidents {
		buckets[shardKey(inc.ID)] = append(buckets[shardKey(inc.ID)], inc)
	}

	// Write shards using compare-before-write; collect every filename we own
	// so we can delete true orphans (files that existed from a prior run but
	// no longer correspond to any bucket).
	owned := map[string]bool{}
	for shard, recs := range buckets {
		names, err := writeShardedJSONL(dir, shard, recs)
		if err != nil {
			return err
		}
		for _, n := range names {
			owned[n] = true
		}
	}

	// Remove only stale shards — files present on disk but not produced this run.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") && !owned[e.Name()] {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}

	// Backward-compat symlink: incidents/all → v1/all so existing consumers
	// that read the unversioned path continue to work.
	ensureSymlink(
		filepath.Join(outputDir, "incidents", "all"),
		filepath.Join("v1", "all"),
	)
	return nil
}

// writeShardedJSONL builds recs into one or more {dir}/{shard}[-N].jsonl
// files in memory, writes each file only when its content differs from what
// is already on disk, and returns the full list of filenames it owns (written
// or unchanged). The caller uses this list to delete true orphans.
func writeShardedJSONL(dir, shard string, recs []*incident.Incident) ([]string, error) {
	if len(recs) == 0 {
		return nil, nil
	}

	// Build sub-shard byte slices in memory so we can compare before writing.
	var subShards [][]byte
	var cur []byte
	for _, r := range recs {
		line, err := json.Marshal(r)
		if err != nil {
			return nil, fmt.Errorf("marshal %s: %w", r.ID, err)
		}
		line = append(line, '\n')
		if len(cur) > 0 && len(cur)+len(line) > maxShardBytes {
			subShards = append(subShards, cur)
			cur = nil
		}
		cur = append(cur, line...)
	}
	if len(cur) > 0 {
		subShards = append(subShards, cur)
	}

	names := make([]string, len(subShards))
	for i, data := range subShards {
		var name string
		if len(subShards) == 1 {
			name = shard + ".jsonl"
		} else {
			name = fmt.Sprintf("%s-%d.jsonl", shard, i)
		}
		names[i] = name
		path := filepath.Join(dir, name)
		if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
			continue // identical — skip the write, don't dirty git
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return nil, err
		}
	}
	return names, nil
}

// LoadAllJSONLShards reads every {outputDir}/incidents/all/*.jsonl shard back
// into memory as []*incident.Incident. It's the read counterpart to
// WriteAllJSONLShards and exists so the sync pipeline can re-merge the
// already-persisted dataset with the new fetch window's results before the
// next persist call — otherwise persist wipes whatever it doesn't see in
// this run, silently destroying any incident not refreshed in the current
// `since` window.
//
// Returns (nil, nil) when the directory doesn't exist (first-run case).
// Malformed lines are skipped with a debug log rather than failing the load,
// because a single corrupt record shouldn't take the whole dataset offline
// — the worst case is one incident missing for one cycle.
func LoadAllJSONLShards(outputDir string) ([]*incident.Incident, error) {
	dir := filepath.Join(outputDir, "incidents", "all")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read all/: %w", err)
	}

	var out []*incident.Incident
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", e.Name(), err)
		}
		scanner := bufio.NewScanner(f)
		// Default scanner buffer is 64 KB; some Trivy-derived container records
		// with 30+ OS-version tuples blow past that. 4 MB header covers any
		// realistic single-incident JSON line.
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			inc := &incident.Incident{}
			if err := json.Unmarshal(line, inc); err != nil {
				continue
			}
			out = append(out, inc)
		}
		_ = f.Close()
	}
	return out, nil
}

// WriteCuratedIndex writes {outputDir}/incidents/index.json with a curated
// IncidentSummary subset suitable for port's main listing.
//
// Selection criteria (union): published in the last `curatedRecentWindow`, OR
// severity in {critical, high}, OR linked to at least one ATT&CK actor. After
// filtering, the list is sorted by published date desc and capped at
// `CuratedIndexCap`.
func WriteCuratedIndex(module string, incidents []*incident.Incident, outputDir string) error {
	now := time.Now().UTC()
	cutoff := now.Add(-CuratedRecentWindow)

	curated := make([]*incident.Incident, 0, len(incidents))
	for _, inc := range incidents {
		if IsCuratedFor(module, inc, cutoff) {
			curated = append(curated, inc)
		}
	}

	sort.Slice(curated, func(i, j int) bool {
		return PublishedAt(curated[i]).After(PublishedAt(curated[j]))
	})
	if cap := CuratedCapFor(module); cap > 0 && len(curated) > cap {
		curated = curated[:cap]
	}

	idx := ModuleIndex{
		SchemaVersion: SchemaVersion,
		Generated:     now.Format(time.RFC3339),
		Module:        module,
		Stats: ModuleIndexStats{
			TotalIncidents: len(incidents),
			TotalIOCs:      countIOCs(incidents),
			LastSync:       now.Format(time.RFC3339),
		},
		Campaigns: buildCampaigns(incidents),
		Incidents: buildIncidentSummaries(curated),
	}

	dest := filepath.Join(outputDir, "incidents", "v1", "index.json")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return err
	}
	// Backward-compat symlink: incidents/index.json → v1/index.json
	ensureSymlink(
		filepath.Join(outputDir, "incidents", "index.json"),
		filepath.Join("v1", "index.json"),
	)
	return nil
}

// ByCVEEntry is one record value in by-cve.json. Mirror of ByPackageEntry
// but keyed by CVE_ID instead of ecosystem/name. Used by buoy/scope/trawl
// to answer "is CVE-X covered by Dragnet?" without downloading the full
// cve or container all/ shards.
type ByCVEEntry struct {
	ID         string  `json:"id"`
	Severity   string  `json:"severity"`
	AttackType string  `json:"attack_type"`
	CVSS       float64 `json:"cvss_score,omitempty"`
	Module     string  `json:"module"`
	Published  string  `json:"published,omitempty"`
	Source     string  `json:"source,omitempty"`
	KEV        bool    `json:"kev,omitempty"`
}

// WriteByCVELookup writes {outputDir}/lookup/by-cve.json. Keys are CVE IDs
// (upper-case "CVE-YYYY-NNNN"); values are lists of incident metadata.
// Only meaningful for modules whose records carry CVE_IDs (cve, container)
// — supply/malware/ransomware skip the call cheaply because their records
// have no CVEExt.
func WriteByCVELookup(module string, incidents []*incident.Incident, outputDir string) error {
	sort.Slice(incidents, func(i, j int) bool { return incidents[i].ID < incidents[j].ID })

	lookup := map[string][]ByCVEEntry{}
	for _, inc := range incidents {
		if inc.CVEExt == nil || inc.CVEExt.CVEID == "" {
			continue
		}
		key := strings.ToUpper(inc.CVEExt.CVEID)
		lookup[key] = append(lookup[key], ByCVEEntry{
			ID:         inc.ID,
			Severity:   inc.Severity,
			AttackType: inc.AttackType,
			CVSS:       inc.CVEExt.CVSSScore,
			Module:     module,
			Published:  inc.CompromiseWindow.Start,
			Source:     inc.Source,
			KEV:        inc.CVEExt.ExploitedInWild,
		})
	}

	// Skip writing for modules whose records don't carry CVEs — avoids a
	// 2-byte `{}` file polluting supply/malware/ransomware/lookup/.
	if len(lookup) == 0 {
		return nil
	}

	dir := filepath.Join(outputDir, "lookup")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	dest := filepath.Join(dir, "by-cve.json")
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(f, 1<<17)
	if encErr := json.NewEncoder(bw).Encode(lookup); encErr != nil {
		f.Close()
		return encErr
	}
	if flushErr := bw.Flush(); flushErr != nil {
		f.Close()
		return flushErr
	}
	return f.Close()
}

// ByPackageEntry is one record value in by-package.json. Rich enough that
// buoy/scope/trawl can render a useful hover/notification without a second
// fetch, while staying small enough to keep the lookup file manageable.
type ByPackageEntry struct {
	ID               string   `json:"id"`
	Severity         string   `json:"severity"`
	AttackType       string   `json:"attack_type"`
	AffectedVersions []string `json:"affected_versions,omitempty"`
	Published        string   `json:"published,omitempty"`
	Source           string   `json:"source,omitempty"`
}

// WriteByPackageLookup writes {outputDir}/lookup/by-package.json. Keys are
// "ecosystem/name"; values are ordered lists of brief incident metadata.
func WriteByPackageLookup(incidents []*incident.Incident, outputDir string) error {
	// Deterministic — see comment in WriteAllJSONLShards.
	sort.Slice(incidents, func(i, j int) bool { return incidents[i].ID < incidents[j].ID })

	lookup := map[string][]ByPackageEntry{}
	for _, inc := range incidents {
		entry := ByPackageEntry{
			ID:         inc.ID,
			Severity:   inc.Severity,
			AttackType: inc.AttackType,
			Published:  inc.CompromiseWindow.Start,
			Source:     inc.Source,
		}
		for _, pkg := range inc.Packages {
			if pkg.Name == "" || pkg.Ecosystem == "" {
				continue
			}
			key := strings.ToLower(pkg.Ecosystem) + "/" + strings.ToLower(pkg.Name)
			e := entry
			if len(pkg.AffectedVersions) > 0 {
				e.AffectedVersions = pkg.AffectedVersions
			}
			lookup[key] = append(lookup[key], e)
		}
	}

	dir := filepath.Join(outputDir, "lookup")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	dest := filepath.Join(dir, "by-package.json")
	// Minified — at 238k unique packages the file is ~40 MB pretty-printed
	// for zero consumer benefit. Clients parse it once.
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(f, 1<<17)
	if encErr := json.NewEncoder(bw).Encode(lookup); encErr != nil {
		f.Close()
		return encErr
	}
	if flushErr := bw.Flush(); flushErr != nil {
		f.Close()
		return flushErr
	}
	return f.Close()
}

// ─── helpers ──────────────────────────────────────────────────────────────

// shardKey picks the alphanumeric prefix of an incident ID, lowercased, as the
// shard filename. The result is always a safe filename — we stop at the first
// non-[a-z0-9] char. Examples:
//
//	"CVE-2024-12345"            → "cve"
//	"ghsa-xxxx-xxxx-xxxx"       → "ghsa"
//	"ossf-abcdef"               → "ossf"
//	"dragnet-supply-2026-0001"  → "dragnet"
//	"packagist:https:/x/y/z"    → "packagist"  (handles weird OSV-style IDs)
//
// IDs without an alphanumeric prefix go to "misc".
func shardKey(id string) string {
	s := strings.ToLower(id)
	end := 0
	for end < len(s) {
		c := s[end]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			break
		}
		end++
	}
	if end == 0 {
		return "misc"
	}
	return s[:end]
}

// IsCurated keeps the legacy module-blind signature for callers that don't
// know which module they're inspecting (sigma eligibility, STIX gating). New
// code should prefer IsCuratedFor so it picks up module-specific relaxations.
func IsCurated(inc *incident.Incident, cutoff time.Time) bool {
	return IsCuratedFor("", inc, cutoff)
}

// IsCuratedFor is the module-aware curation predicate. Per-module relaxations:
//   - supply: also keep "medium" severity. Supply advisories are mostly graded
//     medium by CVSS-adjacent scoring (one compromised npm package isn't
//     "critical" by IT-risk standards) but they're critically important for
//     the trawl/scope/buoy use case. Without this, supply's index.json shows
//     ~0 records even when supply/incidents/all/ has 250k.
//   - other modules: behaviour unchanged — critical/high OR actor-linked OR
//     within the recent window.
func IsCuratedFor(module string, inc *incident.Incident, cutoff time.Time) bool {
	sev := strings.ToLower(inc.Severity)
	switch sev {
	case "critical", "high":
		return true
	}
	if module == "supply" && sev == "medium" {
		return true
	}
	if len(inc.ActorIDs) > 0 {
		return true
	}
	if t := PublishedAt(inc); !t.IsZero() && t.After(cutoff) {
		return true
	}
	return false
}

func PublishedAt(inc *incident.Incident) time.Time {
	if inc.CompromiseWindow.Start == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, inc.CompromiseWindow.Start)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ensureSymlink creates a relative symlink at linkPath pointing to target.
// If an identical symlink already exists it is left in place. A dangling or
// wrong-target symlink is replaced; a real file is never touched so we
// don't accidentally clobber hand-placed content in the haul directory.
func ensureSymlink(linkPath, target string) {
	if existing, err := os.Readlink(linkPath); err == nil && existing == target {
		return // already correct
	}
	if info, err := os.Lstat(linkPath); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return // real file — leave it alone
		}
		_ = os.Remove(linkPath)
	}
	_ = os.Symlink(target, linkPath)
}
