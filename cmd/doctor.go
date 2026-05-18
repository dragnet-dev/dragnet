// Package cmd: `dragnet doctor` is a read-only post-sync health check.
//
// While `validate` checks per-incident YAML files against the schema before
// they enter the pipeline, `doctor` inspects what's on disk AFTER sync/generate
// and reports cross-artifact inconsistencies: orphan sigma rules, stale IOC
// feeds, divergence between stats.total_incidents and actual shard line counts,
// etc. Exits non-zero if any check fails so it can gate workflow commits.
//
// Designed to be cheap (sub-second on the full haul) and never mutate state —
// catching a regression early is the point; over-eager cleanup would risk
// false-positive data loss (see notes in cmd/sync.go around the persist-wipe
// bug that motivated this command).
package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/config"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Report cross-artifact inconsistencies in the generated haul state",
	// Suppress cobra's usage-on-error noise; doctor's whole output is its
	// findings, not a CLI grammar lesson. (SilenceErrors stays false so the
	// "found N inconsistency(ies)" message still prints and the non-zero
	// exit code propagates.)
	SilenceUsage: true,
	RunE:         runDoctor,
}

var (
	doctorModule     string
	doctorRoot       string
	doctorRulesRoot  string
	doctorSTIXRoot   string
)

func init() {
	doctorCmd.Flags().StringVar(&doctorModule, "module", "all",
		"Module to check: supply|malware|ransomware|cve|container|all")
	doctorCmd.Flags().StringVar(&doctorRoot, "root", ".",
		"Intel repo (haul) root to inspect")
	doctorCmd.Flags().StringVar(&doctorRulesRoot, "check-rules", "",
		"haul-rules checkout path. When set, doctor walks {check-rules}/{module}/rules/ "+
			"and verifies every rule file's referenced incident ID exists in haul.")
	doctorCmd.Flags().StringVar(&doctorSTIXRoot, "check-stix", "",
		"haul-stix checkout path. When set, doctor walks {check-stix}/{module}/feeds/stix/ "+
			"and verifies every bundle's referenced incident IDs exist in haul.")
}

// moduleReport captures everything we'll cross-check for one module.
type moduleReport struct {
	module           string
	shardRecordCount int    // sum of lines in incidents/all/*.jsonl
	indexTotal       int    // index.json -> stats.total_incidents
	indexListed      int    // index.json -> len(incidents)
	indexMissing     bool   // index.json doesn't exist
	lookupEntries    int    // by-package.json key count
	lookupMissing    bool
	sigmaRules       int    // count of rules/sigma/**/*.yaml
	feedsIOCs        int    // feeds/unified.jsonl line count (preferred) or unified.json array length
	feedsMissing     bool
}

func runDoctor(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load(filepath.Join(doctorRoot, filepath.Base(cfgFile)))
	if err != nil {
		// Fall through to module-name fallback if no config — useful for
		// synthetic test fixtures that don't ship a full dragnet.yaml.
		log.Printf("[doctor] no dragnet.yaml at root (%v) — falling back to default module names", err)
	}

	moduleNames := resolveModules(doctorModule)

	reports := make([]moduleReport, 0, len(moduleNames))
	knownIDs := map[string]bool{} // for cross-ref check across all modules
	for _, modName := range moduleNames {
		outputDir := modName
		if cfg != nil {
			if mc, ok := cfg.Modules[modName]; ok && mc.OutputDir != "" {
				outputDir = mc.OutputDir
			}
		}
		modRoot := filepath.Join(doctorRoot, outputDir)
		reports = append(reports, inspectModule(modName, modRoot))
		collectKnownIDs(modRoot, knownIDs)
	}

	issues := 0
	for _, r := range reports {
		issues += printReport(r)
	}

	// Cross-reference check: anything in feeds/unified.{json,jsonl} or actor
	// profiles that references an incident ID no shard contains is a dangling
	// pointer. Common after the persist-wipe bug (artifacts kept references
	// to incidents that got wiped). v0.1.10's persist-merge prevents new
	// dangling refs; this check makes the cleanup visible.
	if dangling := checkDangling(doctorRoot, knownIDs); dangling > 0 {
		log.Printf("[doctor][cross-ref] FAIL %d dangling references to unknown incident IDs", dangling)
		issues += dangling
	}

	// v0.1.11+: when --check-rules / --check-stix point at the satellite
	// repos, walk them and verify every cross-repo reference resolves to an
	// incident ID that haul actually has. Catches the failure mode where
	// haul-rules has a rule for an incident that haul itself doesn't list.
	if doctorRulesRoot != "" {
		if missing := checkRulesRepo(doctorRulesRoot, knownIDs); missing > 0 {
			log.Printf("[doctor][rules-ref] FAIL %d rule files reference unknown incident IDs in %s", missing, doctorRulesRoot)
			issues += missing
		} else {
			log.Printf("[doctor][rules-ref] %s: every rule resolves to a haul incident", doctorRulesRoot)
		}
	}
	if doctorSTIXRoot != "" {
		if missing := checkSTIXRepo(doctorSTIXRoot, knownIDs); missing > 0 {
			log.Printf("[doctor][stix-ref] FAIL %d STIX objects reference unknown incident IDs in %s", missing, doctorSTIXRoot)
			issues += missing
		} else {
			log.Printf("[doctor][stix-ref] %s: every STIX object resolves to a haul incident", doctorSTIXRoot)
		}
	}

	if issues > 0 {
		return fmt.Errorf("doctor found %d inconsistency(ies)", issues)
	}
	log.Printf("[doctor] all modules consistent")
	return nil
}

// checkRulesRepo walks {rulesRoot}/{module}/rules/sigma/ for YAML rule files
// and verifies each one's "Incident: <id>" reference (embedded in the rule
// description by the sigma generator) resolves to a haul incident ID in
// `known`. Returns the count of dangling rule files.
//
// Why we check by description-grep instead of parsing YAML: it's fast,
// resilient to template changes, and the "Incident:" tag is a stable
// convention in dragnet's sigma templates. A rule file with no such tag is
// counted as clean (some non-standard rules don't carry one).
func checkRulesRepo(rulesRoot string, known map[string]bool) int {
	missing := 0
	_ = filepath.Walk(rulesRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".yaml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		// Look for the "Incident: <id>" line. Stable convention since v0.1.8.
		idx := strings.Index(string(data), "Incident: ")
		if idx < 0 {
			return nil // no incident tag, can't dangle
		}
		rest := string(data)[idx+len("Incident: "):]
		end := strings.IndexAny(rest, "\n\r")
		if end < 0 {
			end = len(rest)
		}
		id := strings.TrimSpace(rest[:end])
		if id != "" && !known[id] {
			missing++
		}
		return nil
	})
	return missing
}

// checkSTIXRepo walks {stixRoot} for bundle.json (and shards), decodes each
// bundle, and verifies every Indicator/Malware/Vulnerability SDO whose
// external_references include a "dragnet" source-name with the dragnet
// incident ID actually points to an incident in `known`.
//
// Bundle structure (from internal/stix/bundler.go): {type: "bundle",
// objects: [{type, id, ...}, ...]}. We scan each object's
// external_references[].external_id when source_name == "dragnet".
func checkSTIXRepo(stixRoot string, known map[string]bool) int {
	missing := 0
	_ = filepath.Walk(stixRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var bundle struct {
			Objects []map[string]any `json:"objects"`
		}
		if err := json.Unmarshal(data, &bundle); err != nil {
			return nil
		}
		for _, obj := range bundle.Objects {
			refs, _ := obj["external_references"].([]any)
			for _, r := range refs {
				rm, _ := r.(map[string]any)
				if rm["source_name"] != "dragnet" {
					continue
				}
				id, _ := rm["external_id"].(string)
				if id != "" && !known[id] {
					missing++
				}
			}
		}
		return nil
	})
	return missing
}

// collectKnownIDs scans incidents/all/*.jsonl for a module and adds every
// ID (and legacy_id, if present) to the set. Both are valid reference
// targets — a downstream artifact may carry either depending on whether
// it was written pre- or post-canonicalization.
func collectKnownIDs(modRoot string, known map[string]bool) {
	allDir := filepath.Join(modRoot, "incidents", "all")
	entries, err := os.ReadDir(allDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		f, err := os.Open(filepath.Join(allDir, e.Name()))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			var rec map[string]any
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				continue
			}
			if id, ok := rec["id"].(string); ok {
				known[id] = true
			}
			if id, ok := rec["legacy_id"].(string); ok {
				known[id] = true
			}
		}
		_ = f.Close()
	}
}

// checkDangling looks at feeds/unified.{json,jsonl} (root + per-module)
// and actor profiles, counting references to incident IDs not in `known`.
// Logs the top offending files (capped) and returns the total count.
func checkDangling(root string, known map[string]bool) int {
	total := 0

	// Root + per-module unified feeds
	candidates := []string{filepath.Join(root, "feeds", "unified.jsonl")}
	for _, mod := range []string{"supply", "malware", "ransomware", "cve", "container"} {
		candidates = append(candidates, filepath.Join(root, mod, "feeds", "unified.jsonl"))
	}
	for _, path := range candidates {
		n := countDanglingInJSONL(path, known)
		if n > 0 {
			log.Printf("[doctor][cross-ref] %s: %d dangling incident refs", path, n)
			total += n
		}
	}

	// Actor profiles — LinkedIncidents[].incident_id
	actorsDir := filepath.Join(root, "actors", "profiles")
	if entries, err := os.ReadDir(actorsDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			path := filepath.Join(actorsDir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var doc map[string]any
			if err := json.Unmarshal(data, &doc); err != nil {
				continue
			}
			incs, _ := doc["incidents"].([]any)
			n := 0
			for _, item := range incs {
				m, _ := item.(map[string]any)
				id, _ := m["incident_id"].(string)
				if id != "" && !known[id] {
					n++
				}
			}
			if n > 0 {
				log.Printf("[doctor][cross-ref] %s: %d dangling incident refs", path, n)
				total += n
			}
		}
	}

	return total
}

// countDanglingInJSONL inspects each line's "incidents" array for IDs not
// in known. Returns the count of unique dangling IDs in the file.
func countDanglingInJSONL(path string, known map[string]bool) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	dangling := map[string]bool{}
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		ids, _ := rec["incidents"].([]any)
		for _, item := range ids {
			id, _ := item.(string)
			if id != "" && !known[id] {
				dangling[id] = true
			}
		}
	}
	return len(dangling)
}

func inspectModule(name, root string) moduleReport {
	r := moduleReport{module: name}

	// incidents/all/*.jsonl — count records
	allDir := filepath.Join(root, "incidents", "all")
	if entries, err := os.ReadDir(allDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
				continue
			}
			r.shardRecordCount += countLines(filepath.Join(allDir, e.Name()))
		}
	}

	// incidents/index.json — stats.total_incidents + listed count
	indexPath := filepath.Join(root, "incidents", "index.json")
	if data, err := os.ReadFile(indexPath); err == nil {
		var idx struct {
			Stats struct {
				TotalIncidents int `json:"total_incidents"`
			} `json:"stats"`
			Incidents []json.RawMessage `json:"incidents"`
		}
		if err := json.Unmarshal(data, &idx); err == nil {
			r.indexTotal = idx.Stats.TotalIncidents
			r.indexListed = len(idx.Incidents)
		}
	} else if os.IsNotExist(err) {
		r.indexMissing = true
	}

	// lookup/by-package.json — entry count
	lookupPath := filepath.Join(root, "lookup", "by-package.json")
	if data, err := os.ReadFile(lookupPath); err == nil {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(data, &m); err == nil {
			r.lookupEntries = len(m)
		}
	} else if os.IsNotExist(err) {
		r.lookupMissing = true
	}

	// rules/sigma/**/*.yaml — orphan candidate count
	sigmaRoot := filepath.Join(root, "rules", "sigma")
	_ = filepath.Walk(sigmaRoot, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(info.Name(), ".yaml") {
			r.sigmaRules++
		}
		return nil
	})

	// feeds/unified.jsonl (one IOC per line) — preferred over unified.json array.
	feedsJSONL := filepath.Join(root, "feeds", "unified.jsonl")
	feedsJSON := filepath.Join(root, "feeds", "unified.json")
	if n := countLines(feedsJSONL); n > 0 {
		r.feedsIOCs = n
	} else if data, err := os.ReadFile(feedsJSON); err == nil {
		var arr []json.RawMessage
		if err := json.Unmarshal(data, &arr); err == nil {
			r.feedsIOCs = len(arr)
		}
	} else if os.IsNotExist(err) {
		r.feedsMissing = true
	}

	return r
}

// printReport emits human-readable findings and returns the number of issues
// (so the caller can compute an exit code). An "issue" is anything a future
// regression test would want to fail on; warnings that are intentional (e.g.
// index listed == CuratedIndexCap when total > cap) are emitted but don't count.
func printReport(r moduleReport) int {
	issues := 0
	header := fmt.Sprintf("[doctor][%s] shards=%d  index.total=%d  index.listed=%d  lookup=%d  sigma=%d  feeds=%d",
		r.module, r.shardRecordCount, r.indexTotal, r.indexListed, r.lookupEntries, r.sigmaRules, r.feedsIOCs)
	log.Print(header)

	// Cross-checks.
	// 1. Orphan rules: any sigma without any incident is a red flag.
	if r.shardRecordCount == 0 && r.sigmaRules > 0 {
		log.Printf("[doctor][%s] FAIL orphan rules: %d sigma files on disk but 0 incidents in incidents/all/", r.module, r.sigmaRules)
		issues++
	}

	// 2. Orphan IOC feeds: same shape.
	if r.shardRecordCount == 0 && r.feedsIOCs > 0 {
		log.Printf("[doctor][%s] FAIL orphan feeds: %d IOCs in feeds/unified.{json,jsonl} but 0 incidents", r.module, r.feedsIOCs)
		issues++
	}

	// 3. Shard vs index drift. index.total is computed at sync time from the
	//    merged set; shard line count is what got persisted. Small drift can
	//    happen if writeShardedJSONL skips a malformed record, but >1% is a
	//    real problem.
	if r.shardRecordCount > 0 && r.indexTotal > 0 {
		diff := r.indexTotal - r.shardRecordCount
		if diff < 0 {
			diff = -diff
		}
		if diff*100 > r.indexTotal { // >1%
			log.Printf("[doctor][%s] FAIL shard/index drift: stats.total_incidents=%d but disk=%d (gap %d)",
				r.module, r.indexTotal, r.shardRecordCount, diff)
			issues++
		} else if diff > 0 {
			log.Printf("[doctor][%s] WARN shard/index drift (within 1%%): stats=%d disk=%d gap=%d",
				r.module, r.indexTotal, r.shardRecordCount, diff)
		}
	}

	// 4. index.json missing while shards exist — port can't list anything.
	if r.indexMissing && r.shardRecordCount > 0 {
		log.Printf("[doctor][%s] FAIL incidents/index.json missing but %d records on disk", r.module, r.shardRecordCount)
		issues++
	}

	// 5. lookup missing — buoy/scope/trawl break. Only meaningful for the
	//    supply module: cve/container/malware/ransomware records aren't keyed
	//    by "ecosystem/name" (CVEs are keyed by CVE_ID, hashes by hash, etc.),
	//    so by-package.json is correctly empty for those modules and missing
	//    it is fine. Supply is the headline ecosystem-keyed dataset and a
	//    missing lookup there breaks scope/trawl/buoy package checks.
	if r.module == "supply" && r.lookupMissing && r.shardRecordCount > 0 {
		log.Printf("[doctor][%s] FAIL lookup/by-package.json missing but %d records on disk", r.module, r.shardRecordCount)
		issues++
	}

	// 6. Sigma rule glut. If a module has >100 sigma rules per incident, the
	//    rules directory is full of stale orphans from prior runs (e.g. before
	//    a curation tightening or an incident schema migration). Doesn't break
	//    consumers but does bloat git and confuse search tooling.
	if r.shardRecordCount > 0 && r.sigmaRules > 100*r.shardRecordCount {
		log.Printf("[doctor][%s] FAIL sigma rule glut: %d rules for %d incidents (>100x — stale orphans likely)",
			r.module, r.sigmaRules, r.shardRecordCount)
		issues++
	}

	// Curated cap is intentional — index.listed == CuratedIndexCap (5000)
	// when total > 5000 is normal, not a failure. No check needed.

	return issues
}

func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	n := 0
	for sc.Scan() {
		n++
	}
	return n
}
