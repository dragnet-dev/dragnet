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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

// curatedIndexCap is the maximum number of IncidentSummary records emitted into
// index.json. Anything beyond this stays accessible via all/{shard}.jsonl but
// won't be in the front-page listing.
const curatedIndexCap = 5000

// curatedRecentWindow is the rolling window over which all incidents are kept
// regardless of severity / actor link.
const curatedRecentWindow = 90 * 24 * time.Hour

// maxIncidentsPerShard caps the per-shard jsonl size to stay well under GitHub's
// 100 MB single-file limit. The OSSF malicious-packages dump alone produces
// ~225k incidents; without sub-sharding it would balloon to ~240 MB.
// 50k × ~1.1KB/incident ≈ 55 MB per shard — safe margin.
const maxIncidentsPerShard = 50_000

// WriteAllJSONLShards writes every incident in `incidents` to
// {outputDir}/incidents/all/{shard}.jsonl, sharded by ID prefix so each file
// stays well under git's practical size limits.
func WriteAllJSONLShards(incidents []*incident.Incident, outputDir string) error {
	dir := filepath.Join(outputDir, "incidents", "all")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir all/: %w", err)
	}

	// Wipe stale shards first so a shrinking dataset doesn't leave orphans.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}

	// Bucket by shard key, then write each bucket as one .jsonl file.
	buckets := map[string][]*incident.Incident{}
	for _, inc := range incidents {
		buckets[shardKey(inc.ID)] = append(buckets[shardKey(inc.ID)], inc)
	}

	for shard, recs := range buckets {
		// Sub-shard if a single bucket would exceed our per-file budget.
		// Names go {prefix}.jsonl when one part is enough, otherwise
		// {prefix}-0.jsonl, {prefix}-1.jsonl, etc.
		if len(recs) <= maxIncidentsPerShard {
			path := filepath.Join(dir, shard+".jsonl")
			if err := writeJSONL(path, recs); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
			continue
		}
		for i, off := 0, 0; off < len(recs); i, off = i+1, off+maxIncidentsPerShard {
			end := off + maxIncidentsPerShard
			if end > len(recs) {
				end = len(recs)
			}
			path := filepath.Join(dir, fmt.Sprintf("%s-%d.jsonl", shard, i))
			if err := writeJSONL(path, recs[off:end]); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
		}
	}
	return nil
}

// WriteCuratedIndex writes {outputDir}/incidents/index.json with a curated
// IncidentSummary subset suitable for port's main listing.
//
// Selection criteria (union): published in the last `curatedRecentWindow`, OR
// severity in {critical, high}, OR linked to at least one ATT&CK actor. After
// filtering, the list is sorted by published date desc and capped at
// `curatedIndexCap`.
func WriteCuratedIndex(module string, incidents []*incident.Incident, outputDir string) error {
	now := time.Now().UTC()
	cutoff := now.Add(-curatedRecentWindow)

	curated := make([]*incident.Incident, 0, len(incidents))
	for _, inc := range incidents {
		if isCurated(inc, cutoff) {
			curated = append(curated, inc)
		}
	}

	sort.Slice(curated, func(i, j int) bool {
		return publishedAt(curated[i]).After(publishedAt(curated[j]))
	})
	if len(curated) > curatedIndexCap {
		curated = curated[:curatedIndexCap]
	}

	idx := ModuleIndex{
		Generated: now.Format(time.RFC3339),
		Module:    module,
		Stats: ModuleIndexStats{
			TotalIncidents: len(incidents),
			TotalIOCs:      countIOCs(incidents),
			LastSync:       now.Format(time.RFC3339),
		},
		Campaigns: buildCampaigns(incidents),
		Incidents: buildIncidentSummaries(curated),
	}

	dest := filepath.Join(outputDir, "incidents", "index.json")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
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
	data, err := json.Marshal(lookup)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
}

// ─── helpers ──────────────────────────────────────────────────────────────

func writeJSONL(path string, incidents []*incident.Incident) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	bw := bufio.NewWriterSize(f, 1<<20)
	enc := json.NewEncoder(bw)
	for _, inc := range incidents {
		if err := enc.Encode(inc); err != nil {
			return err
		}
	}
	return bw.Flush()
}

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

func isCurated(inc *incident.Incident, cutoff time.Time) bool {
	switch strings.ToLower(inc.Severity) {
	case "critical", "high":
		return true
	}
	if len(inc.ActorIDs) > 0 {
		return true
	}
	if t := publishedAt(inc); !t.IsZero() && t.After(cutoff) {
		return true
	}
	return false
}

func publishedAt(inc *incident.Incident) time.Time {
	if inc.CompromiseWindow.Start == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, inc.CompromiseWindow.Start)
	if err != nil {
		return time.Time{}
	}
	return t
}
