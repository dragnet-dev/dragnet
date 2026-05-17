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
const CuratedRecentWindow = 90 * 24 * time.Hour

// maxShardBytes caps the per-shard jsonl size to stay under GitHub's 50 MB
// soft-warning threshold (hard limit is 100 MB). Size-based sharding handles
// the wide variance in record size — npm advisories are ~1 KB each, but a
// single Trivy CVE that affects 30+ OS-version tuples runs to ~3 KB. Without
// size-based capping, a Trivy shard of 40k records hits ~100 MB and triggers
// GitHub's reject path.
const maxShardBytes = 45 * 1024 * 1024 // 45 MB, leaves headroom under 50 MB warning

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
		// Stream into sub-shards, opening a new one when the current one
		// crosses maxShardBytes. First sub-shard is {prefix}.jsonl; if a
		// second one is needed we rename it to {prefix}-0.jsonl and continue
		// with -1, -2, ...
		if err := writeShardedJSONL(dir, shard, recs); err != nil {
			return err
		}
	}
	return nil
}

// writeShardedJSONL writes recs into one or more {dir}/{shard}[-N].jsonl files,
// rolling to the next sub-shard when the current file would exceed
// maxShardBytes. Returns the first IO error encountered.
func writeShardedJSONL(dir, shard string, recs []*incident.Incident) error {
	if len(recs) == 0 {
		return nil
	}
	subIdx := 0
	subStart := 0
	subBytes := 0
	flush := func(end int) error {
		var name string
		if subIdx == 0 && end == len(recs) {
			name = shard + ".jsonl" // single shard, no suffix
		} else {
			name = fmt.Sprintf("%s-%d.jsonl", shard, subIdx)
		}
		path := filepath.Join(dir, name)
		return writeJSONL(path, recs[subStart:end])
	}
	for i, r := range recs {
		bytes, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", r.ID, err)
		}
		// +1 for newline. If this record would push us over the budget AND
		// we already have at least one record in the current sub-shard, flush.
		if subBytes > 0 && subBytes+len(bytes)+1 > maxShardBytes {
			if err := flush(i); err != nil {
				return err
			}
			subIdx++
			subStart = i
			subBytes = 0
		}
		subBytes += len(bytes) + 1
	}
	return flush(len(recs))
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
	cutoff := now.Add(-CuratedRecentWindow)

	curated := make([]*incident.Incident, 0, len(incidents))
	for _, inc := range incidents {
		if IsCurated(inc, cutoff) {
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

func IsCurated(inc *incident.Incident, cutoff time.Time) bool {
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
