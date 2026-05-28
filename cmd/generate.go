package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dragnet-dev/dragnet/internal/backends"
	"github.com/dragnet-dev/dragnet/internal/config"
	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/dragnet-dev/dragnet/internal/index"
	"github.com/dragnet-dev/dragnet/internal/ioc"
	"github.com/dragnet-dev/dragnet/internal/stix"
	"github.com/spf13/cobra"
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Compile Sigma rules to all backend formats and produce feeds",
	RunE:  runGenerate,
}

var (
	genModule            string
	genBackends          string
	genLayers            string
	genCSIOCAction       string
	genRulesRoot         string
	genSTIXRoot          string
	genCompiledRootBase  string
)

func init() {
	generateCmd.Flags().StringVar(&genModule, "module", "all",
		"Module to generate for: supply|malware|ransomware|cve|all")
	generateCmd.Flags().StringVar(&genBackends, "backends", "all",
		"Comma-separated backends to compile, or 'all'")
	generateCmd.Flags().StringVar(&genLayers, "layers", "all",
		"Comma-separated sigma layer subdirectory names to compile, or 'all' to compile every layer present on disk")
	generateCmd.Flags().StringVar(&genCSIOCAction, "cs-ioc-action", "detect",
		"CrowdStrike IOC action: detect or prevent")
	generateCmd.Flags().StringVar(&genRulesRoot, "rules-root", "",
		"Write rule files under {rules-root}/{module}/rules/... instead of inline. "+
			"Used by the haul workflow to push rules to the haul-rules satellite repo.")
	generateCmd.Flags().StringVar(&genSTIXRoot, "stix-root", "",
		"Write STIX bundles under {stix-root}/feeds/stix and {stix-root}/{module}/feeds/stix. "+
			"Used by the haul workflow to push bundles to the haul-stix satellite repo.")
	generateCmd.Flags().StringVar(&genCompiledRootBase, "compiled-root-base", "",
		"Base path for per-backend satellite repos. Each backend writes to "+
			"{compiled-root-base}-{backend}/{module}/rules/{backend}/. "+
			"Pair with --rules-root pointing at the sigma source repo. "+
			"Mutually exclusive with --rules-root acting as the compiled output root.")
}

func runGenerate(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}

	moduleNames := resolveModules(genModule)
	explicitModule := genModule != "all"

	var be []backends.Backend
	if genBackends == "all" {
		be = backends.All(genCSIOCAction)
	} else {
		var err error
		be, err = backends.ByName(strings.Split(genBackends, ","), genCSIOCAction)
		if err != nil {
			return err
		}
	}

	// explicitLayers is non-nil only when the caller names specific layers.
	// nil means "all layers" — we walk every subdir of sigmaRoot at runtime
	// so new layer names (cve, malware, ransomware, container, …) are picked
	// up automatically without updating this list.
	var explicitLayers map[string]bool
	if genLayers != "all" {
		explicitLayers = map[string]bool{}
		for _, l := range strings.Split(genLayers, ",") {
			explicitLayers[l] = true
		}
	}

	wantSTIX := genBackends == "all" || slices.Contains(strings.Split(genBackends, ","), "stix")

	allModuleIncidents := map[string][]*incident.Incident{}

	for _, modName := range moduleNames {
		modCfg, ok := cfg.Modules[modName]
		if !ok {
			if explicitModule {
				return fmt.Errorf("unknown module %q", modName)
			}
			log.Printf("[generate] skipping module %q (not configured in dragnet.yaml)", modName)
			continue
		}

		// Load incidents first so we can prune stale sigma rules during the
		// file walk below. Pruning here means stale files are never fed to
		// compileBackendsParallel and are removed from the sigma satellite
		// before the push step, which keeps doctor's rules-ref check clean.
		incidentsDir := filepath.Join(modCfg.OutputDir, "incidents")
		modIncidents, err := loadModuleIncidentsFromShards(modName, incidentsDir)
		if err != nil {
			log.Printf("[generate][%s] load incidents: %v", modName, err)
		}
		allModuleIncidents[modName] = modIncidents

		knownIDs := make(map[string]bool, len(modIncidents))
		for _, inc := range modIncidents {
			if inc.ID != "" {
				knownIDs[inc.ID] = true
			}
		}

		// Sigma rule source files. v0.1.11: when --rules-root is set, source
		// sigma YAMLs live there too (written by sync). Read from the same
		// root we'll write the compiled-backend outputs to so the relative
		// path math in moduleRuleOutputPath stays consistent.
		//
		// v0.1.12 fix: the sigma generator writes to {layer}/{year}/*.yaml
		// (two levels deep). The previous os.ReadDir only saw the year
		// directories as entries and skipped them — meaning compiled
		// backends (Splunk, KQL, Elastic, etc.) silently went unwritten
		// for any sync that landed in a year subdir. Walk recursively.
		rulesDir := moduleRulesDir(genRulesRoot, modCfg.OutputDir)
		sigmaRoot := filepath.Join(rulesDir, "sigma")
		var sigmaFiles []string
		pruned := 0
		if entries, err := os.ReadDir(sigmaRoot); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				if explicitLayers != nil && !explicitLayers[entry.Name()] {
					continue
				}
				layerRoot := filepath.Join(sigmaRoot, entry.Name())
				err := filepath.WalkDir(layerRoot, func(path string, d os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if d.IsDir() || !strings.HasSuffix(d.Name(), ".yaml") {
						return nil
					}
					// Prune rules whose incident ID is no longer in haul.
					// Only prune when we have a non-empty incident set — an
					// empty set means incidents failed to load, not that all
					// incidents were removed.
					if len(knownIDs) > 0 {
						data, readErr := os.ReadFile(path)
						if readErr == nil {
							if id := extractIncidentID(data); id != "" && !knownIDs[id] {
								if removeErr := os.Remove(path); removeErr == nil {
									pruned++
									return nil
								}
							}
						}
					}
					sigmaFiles = append(sigmaFiles, path)
					return nil
				})
				if err != nil {
					return err
				}
			}
		}
		if pruned > 0 {
			log.Printf("[generate][%s] pruned %d stale sigma rule(s) referencing unknown incident IDs", modName, pruned)
		}

		// Compiled-backend output root. Three modes:
		//   per-backend: --compiled-root-base ../haul-rules → each backend
		//                writes to ../haul-rules-{backend}/{module}/rules/
		//   external:    --rules-root ../haul-rules (no compiled-root-base) →
		//                all backends under ../haul-rules/{module}/rules/
		//   inline:      no flags → {module}/rules/{backend}/ in the haul tree
		var rootFor func(backendName string) string
		switch {
		case genCompiledRootBase != "":
			rootFor = func(bname string) string {
				return compiledRootForBackend(genCompiledRootBase, bname, modCfg.OutputDir)
			}
		case genRulesRoot != "":
			root := filepath.Join(genRulesRoot, filepath.Base(modCfg.OutputDir))
			rootFor = func(_ string) string { return root }
		default:
			rootFor = func(_ string) string { return modCfg.OutputDir }
		}
		compileBackendsParallel(modName, sigmaFiles, be, sigmaRoot, rootFor)

		// IOC-native backends (YARA etc.) generate from incident JSON, not Sigma.
		// Activated when --backends all or when "yara" is explicitly named.
		wantYARA := genBackends == "all" || slices.Contains(strings.Split(genBackends, ","), "yara")
		if wantYARA {
			iocNative := backends.AllIOCNative()
			if err := compileIOCNativeBackends(modName, modIncidents, iocNative, rootFor); err != nil {
				log.Printf("[generate][%s] ioc-native backends: %v", modName, err)
			}
		}

		// Backfill DetectionRules into incidents. Scan every rule output
		// directory (sigma source + all compiled backends) for files whose
		// names start with a known incident ID, then write the associations
		// back to the JSONL shards so port/buoy/scope can link directly to
		// detection content without walking satellite repos themselves.
		backfillDetectionRules(modName, modIncidents, sigmaRoot, be, rootFor, wantYARA)
		if err := index.WriteAllJSONLShards(modIncidents, modCfg.OutputDir); err != nil {
			log.Printf("[generate][%s] rewrite shards with detection_rules: %v", modName, err)
		}

		if wantSTIX {
			stixOutDir := moduleSTIXDir(genSTIXRoot, modCfg.OutputDir)
			if err := writeModuleSTIX(modName, modIncidents, stixOutDir); err != nil {
				log.Printf("[generate][%s] stix: %v", modName, err)
			}

			// Don't overwrite the curated index.json that sync wrote unless
			// generate is run standalone (no all/ dir exists).
			allDir := filepath.Join(incidentsDir, "all")
			if _, err := os.Stat(allDir); os.IsNotExist(err) {
				if err := index.WriteCuratedIndex(modName, modIncidents, modCfg.OutputDir); err != nil {
					log.Printf("[generate][%s] index: %v", modName, err)
				}
			} else {
				log.Printf("[generate][%s] index: skipped (sync already wrote it from full dataset)", modName)
			}

			iocExp := ioc.New()
			feedsDir := filepath.Join(modCfg.OutputDir, "feeds")
			for _, inc := range modIncidents {
				if err := iocExp.Export(inc, feedsDir); err != nil {
					log.Printf("[generate][%s] ioc export %s: %v", modName, inc.ID, err)
				}
			}
		}
	}

	// Search index — writes BEFORE root STIX so it always lands even if
	// STIX bundle validation runs slow on the full 450k-incident set.
	if len(allModuleIncidents) > 0 {
		if err := index.WriteSearchIndex(allModuleIncidents, "."); err != nil {
			log.Printf("[generate] search index: %v", err)
		} else {
			log.Printf("[generate] search index: wrote per-module feeds/search-*.jsonl")
		}
	}

	// Root combined outputs.
	if wantSTIX && len(allModuleIncidents) > 0 {
		if err := index.GenerateRootIndex(allModuleIncidents, "."); err != nil {
			log.Printf("[generate] root index: %v", err)
		}

		moduleFeedDirs := map[string]string{}
		for modName, modCfg := range cfg.Modules {
			moduleFeedDirs[modName] = filepath.Join(modCfg.OutputDir, "feeds")
		}
		if err := ioc.ExportCombined(moduleFeedDirs, "feeds"); err != nil {
			log.Printf("[generate] combined feeds: %v", err)
		}

		if err := generateRootSTIX(allModuleIncidents); err != nil {
			log.Printf("[generate] root stix: %v", err)
		}
	}

	return nil
}

// loadModuleIncidentsFromShards reads {incidentsDir}/all/*.jsonl into memory.
// Used by both STIX and search index generation.
func loadModuleIncidentsFromShards(modName, incidentsDir string) ([]*incident.Incident, error) {
	var out []*incident.Incident
	allDir := filepath.Join(incidentsDir, "all")
	entries, _ := os.ReadDir(allDir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		incs, err := loadIncidentsJSONL(filepath.Join(allDir, e.Name()))
		if err != nil {
			log.Printf("[generate][%s] load %s: %v", modName, e.Name(), err)
			continue
		}
		out = append(out, incs...)
	}
	return out, nil
}

// writeModuleSTIX builds and writes the per-module combined STIX bundle from
// pre-loaded incidents. The set is filtered + capped to mirror index.json
// exactly:
//
//  1. Keep only IsCurated incidents (severe / actor-linked / published in the
//     last 90 days).
//  2. Sort by published date desc.
//  3. Cap at index.CuratedIndexCap (currently 5000 per module).
//
// The bulk dataset stays available via JSONL shards; STIX is for SIEM/TIP
// ingestion which wants the same "actionable, recent" subset that port shows
// on its front page. Without the cap, OSV bulk (mostly severity=high)
// ballooned to ~224k bundles per supply run, dragging generate to 13+ min
// and producing a >100 MB bundle.json that GitHub's push hook rejects.
//
// Two runtime optimisations make this fast and safe:
//
//   - stix.GenerateBundle calls are fanned out across runtime.NumCPU()
//     workers (~4x wall-time reduction on 4-core runners). Bundle build is
//     pure (no I/O, reads-only of the global actorStore) so concurrency is
//     safe.
//   - The combined bundle is streamed to disk via WriteCombinedBundleShards,
//     which rolls into bundle-N.json shards at MaxBundleShardBytes (~40 MB
//     each). Single-shard output keeps the legacy "bundle.json" filename;
//     multi-shard runs renumber from -0.
//
// Per-incident bundle validation and combined-bundle validation are both
// skipped — the cost dominated the v0.1.7 hang; structural correctness of
// the combined doc is implied by sub-bundle correctness.
func writeModuleSTIX(modName string, incidents []*incident.Incident, stixOutDir string) error {
	cutoff := time.Now().UTC().Add(-index.CuratedRecentWindow)

	curated := make([]*incident.Incident, 0, len(incidents))
	for _, inc := range incidents {
		if index.IsCuratedFor(modName, inc, cutoff) {
			curated = append(curated, inc)
		}
	}
	// Per-module cap applies when STIX bundles live inline in haul
	// (legacy). With --stix-root pointing at haul-stix, bundles get their
	// own repo and the cap is dropped — the full curated set lands in the
	// satellite bundle.
	if genSTIXRoot == "" {
		sort.Slice(curated, func(i, j int) bool {
			return index.PublishedAt(curated[i]).After(index.PublishedAt(curated[j]))
		})
		if cap := index.CuratedCapFor(modName); cap > 0 && len(curated) > cap {
			curated = curated[:cap]
		}
	}

	bundles := buildBundlesParallel(curated)
	if genSTIXRoot == "" {
		log.Printf("[generate][%s] stix: built %d bundles (curated, capped at %d, of %d total)",
			modName, len(bundles), index.CuratedCapFor(modName), len(incidents))
	} else {
		log.Printf("[generate][%s] stix: built %d bundles (curated, uncapped — split mode, of %d total)",
			modName, len(bundles), len(incidents))
	}

	if len(bundles) == 0 {
		return nil
	}

	shards, err := stix.WriteCombinedBundleShards(stixOutDir, "bundle", bundles)
	if err != nil {
		return fmt.Errorf("write %s stix shards: %w", modName, err)
	}
	if len(shards) > 1 {
		log.Printf("[generate][%s] stix: sharded into %d files (%v) to stay under GitHub's 100 MB cap", modName, len(shards), shards)
	}
	return nil
}

// networkOnlyBackends only produce meaningful output for network-layer Sigma
// rules. Skip non-network files entirely to avoid writing comment-stub
// placeholders that add noise to the satellite repos.
var networkOnlyBackends = map[string]bool{
	"suricata": true,
	"snort":    true,
}

// networkCategories are the logsource categories that produce network rules.
var networkCategories = map[string]bool{
	"network_connection": true,
	"dns_query":          true,
	"network_traffic":    true,
	"proxy":              true,
}

// reLogsourceCategory extracts the logsource.category value from a Sigma YAML
// using a lightweight regex rather than a full parse — category is always at
// 2-space indentation inside the logsource block in our generated files.
var reLogsourceCategory = regexp.MustCompile(`(?m)^  category:\s*(\S+)`)

func sigmaCategory(data []byte) string {
	m := reLogsourceCategory.Find(data)
	if m == nil {
		return ""
	}
	parts := strings.SplitN(string(m), ":", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// compileBackendsParallel runs the (rule × backend) compile cartesian
// across runtime.NumCPU() workers. Each backend's Compile() is pure — it
// parses the Sigma YAML into the backend's native rule format — so workers
// can run independently. Output is incremental: writeFileIfChanged skips
// the write entirely when the compiled bytes match what's already on disk,
// which both shaves I/O and avoids dirtying the git index when nothing
// substantive changed.
// compileBackendsParallel compiles every (sigmaFile × backend) pair.
// rootFor maps a backend name to the module output root for that backend —
// either a constant (single-repo mode) or a per-backend path (split mode).
func compileBackendsParallel(modName string, sigmaFiles []string, be []backends.Backend, sigmaRoot string, rootFor func(string) string) {
	type job struct {
		sf      string
		data    []byte
		backend backends.Backend
	}

	// Pre-read all sigma rule files. Reads are cheap (~ms each), and doing
	// it serially up-front lets us share the same data byte-slice across
	// every backend's compile call rather than re-reading per-backend.
	dataByFile := make(map[string][]byte, len(sigmaFiles))
	for _, sf := range sigmaFiles {
		data, err := os.ReadFile(sf)
		if err != nil {
			log.Printf("[generate][%s] read %s: %v", modName, sf, err)
			continue
		}
		dataByFile[sf] = data
	}

	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan job, workers*2)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				out, err := j.backend.Compile(j.data)
				if err != nil {
					log.Printf("[generate][%s] %s compile %s: %v", modName, j.backend.Name(), j.sf, err)
					continue
				}
				dest := moduleRuleOutputPath(j.backend, j.sf, sigmaRoot, rootFor(j.backend.Name()))
				if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
					log.Printf("[generate][%s] mkdir %s: %v", modName, dest, err)
					continue
				}
				if err := writeFileIfChanged(dest, out, 0o644); err != nil {
					log.Printf("[generate][%s] write %s: %v", modName, dest, err)
				}
			}
		}()
	}
	for _, sf := range sigmaFiles {
		data, ok := dataByFile[sf]
		if !ok {
			continue
		}
		cat := sigmaCategory(data)
		for _, b := range be {
			// Network-only backends (Suricata, Snort) only produce useful output
			// for network-layer rules. Skip non-network files to avoid writing
			// comment-stub placeholders into the satellite repos.
			if networkOnlyBackends[b.Name()] && !networkCategories[cat] {
				continue
			}
			jobs <- job{sf: sf, data: data, backend: b}
		}
	}
	close(jobs)
	wg.Wait()
}

// writeFileIfChanged reads the existing file (if any) and only writes when
// the bytes differ. Avoids touching unchanged sigma/IOC/STIX outputs across
// runs, which keeps git diffs honest (only real content changes appear) and
// halves IO on stable steady-state runs.
func writeFileIfChanged(path string, data []byte, perm os.FileMode) error {
	if existing, err := os.ReadFile(path); err == nil {
		if len(existing) == len(data) && bytes.Equal(existing, data) {
			return nil
		}
	}
	return os.WriteFile(path, data, perm)
}

// buildBundlesParallel fans stix.GenerateBundle across runtime.NumCPU()
// workers and returns the resulting bundles in input order. Order
// preservation matters for manifest sha256 determinism — same input must
// produce byte-identical output.
//
// stix.GenerateBundle is safe to call concurrently: it reads the package-
// global actorStore (set once via stix.SetActorStore at sync init) but
// doesn't mutate it, allocates a fresh Bundle struct per call, and does
// no I/O.
func buildBundlesParallel(incidents []*incident.Incident) []stix.Bundle {
	n := len(incidents)
	if n == 0 {
		return nil
	}
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8 // GitHub runners are 4-core; cap at 8 for any beefier env
	}
	if workers > n {
		workers = n
	}

	out := make([]stix.Bundle, n)
	type job struct{ idx int }
	jobs := make(chan job, workers*2)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				out[j.idx] = stix.GenerateBundle(incidents[j.idx])
			}
		}()
	}
	for i := range incidents {
		jobs <- job{idx: i}
	}
	close(jobs)
	wg.Wait()
	return out
}

// loadIncidentsJSONL parses one shard file (newline-delimited JSON Incidents)
// from the sync's persist output and returns the records.
func loadIncidentsJSONL(path string) ([]*incident.Incident, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []*incident.Incident
	dec := json.NewDecoder(f)
	for dec.More() {
		var inc incident.Incident
		if err := dec.Decode(&inc); err != nil {
			return out, err
		}
		out = append(out, &inc)
	}
	return out, nil
}

// generateRootSTIX produces the cross-module combined bundle by reusing
// each module's curated subset. We apply the same IsCurated filter + cap
// per-module (so root reflects the same selection as the per-module bundles
// and the index.json listings), then build bundles in parallel, then stream
// out to shards at feeds/stix/bundle{-N}.json.
//
// Per-module STIX is the primary artifact for SIEM consumers (they ingest
// by domain); root is the "everything in one ingest" convenience artifact.
// Sharded output is still consumable — each shard is a valid standalone
// STIX bundle.
func generateRootSTIX(allModules map[string][]*incident.Incident) error {
	cutoff := time.Now().UTC().Add(-index.CuratedRecentWindow)
	var curated []*incident.Incident
	for modName, incidents := range allModules {
		modCurated := make([]*incident.Incident, 0)
		for _, inc := range incidents {
			if index.IsCuratedFor(modName, inc, cutoff) {
				modCurated = append(modCurated, inc)
			}
		}
		// Per-module cap applies inline; dropped when bundles live in haul-stix.
		if genSTIXRoot == "" {
			sort.Slice(modCurated, func(i, j int) bool {
				return index.PublishedAt(modCurated[i]).After(index.PublishedAt(modCurated[j]))
			})
			if cap := index.CuratedCapFor(modName); cap > 0 && len(modCurated) > cap {
				modCurated = modCurated[:cap]
			}
		}
		curated = append(curated, modCurated...)
	}

	bundles := buildBundlesParallel(curated)
	if len(bundles) == 0 {
		return nil
	}

	shards, err := stix.WriteCombinedBundleShards(rootSTIXDir(genSTIXRoot), "bundle", bundles)
	if err != nil {
		return fmt.Errorf("write root stix shards: %w", err)
	}
	log.Printf("[generate] root stix: %d bundles across %d shard(s) (%v)", len(bundles), len(shards), shards)
	return nil
}

func moduleRuleOutputPath(b backends.Backend, sigmaFile, sigmaRoot, moduleOutputDir string) string {
	rel, err := filepath.Rel(sigmaRoot, sigmaFile)
	if err != nil {
		rel = filepath.Base(sigmaFile)
	}
	ext := b.OutputExtension()
	base := strings.TrimSuffix(rel, filepath.Ext(rel)) + ext
	return filepath.Join(moduleOutputDir, "rules", b.Name(), base)
}

// compileIOCNativeBackends generates rules from incident data for backends that
// implement IOCNativeBackend (e.g. YARA). Writes individual rule files and a
// per-module bundle file. Uses writeFileIfChanged to avoid spurious git diffs.
func compileIOCNativeBackends(
	modName string,
	incidents []*incident.Incident,
	iocBackends []backends.IOCNativeBackend,
	rootFor func(string) string,
) error {
	for _, b := range iocBackends {
		root := rootFor(b.Name())
		rulesDir := filepath.Join(root, "rules", b.Name())

		// Extract module name from the first incident's ID (dragnet-{module}-…)
		// for the per-module subdirectory. Fall back to modName.
		moduleSlug := modName

		var bundle []byte
		written, skipped := 0, 0

		for _, inc := range incidents {
			rule, err := b.GenerateFromIncident(inc)
			if err != nil {
				log.Printf("[generate][%s] %s generate %s: %v", modName, b.Name(), inc.ID, err)
				continue
			}
			if rule == nil {
				skipped++
				continue
			}

			// Derive year from compromise window start or fall back to current year.
			year := "unknown"
			if inc.CompromiseWindow.Start != "" && len(inc.CompromiseWindow.Start) >= 4 {
				year = inc.CompromiseWindow.Start[:4]
			}

			outDir := filepath.Join(rulesDir, moduleSlug, year)
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				log.Printf("[generate][%s] %s mkdir %s: %v", modName, b.Name(), outDir, err)
				continue
			}
			fname := sanitizeFilename(inc.ID) + b.OutputExtension()
			dest := filepath.Join(outDir, fname)
			if err := writeFileIfChanged(dest, rule, 0o644); err != nil {
				log.Printf("[generate][%s] %s write %s: %v", modName, b.Name(), dest, err)
				continue
			}
			written++
			bundle = append(bundle, rule...)
			if !bytes.HasSuffix(bundle, []byte("\n\n")) {
				bundle = append(bundle, '\n')
			}
		}

		if len(bundle) > 0 {
			bundleDest := filepath.Join(rulesDir, "bundle"+b.OutputExtension())
			if err := os.MkdirAll(filepath.Dir(bundleDest), 0o755); err == nil {
				if err := writeFileIfChanged(bundleDest, bundle, 0o644); err != nil {
					log.Printf("[generate][%s] %s bundle write: %v", modName, b.Name(), err)
				}
			}
		}

		log.Printf("[generate][%s] %s: %d rules written, %d skipped (no usable IOCs)", modName, b.Name(), written, skipped)
	}
	return nil
}

// backfillDetectionRules scans all rule output directories for files matching
// each incident's dragnet ID and writes the results to inc.DetectionRules.
// This lets port/buoy/scope display the detection rules accordion without
// walking satellite repos — incidents carry their own rule manifest.
//
// Scan order: sigma source dir first, then each compiled backend dir, then
// IOC-native (YARA) dir. Only sigma and IOC-native backends produce files named
// directly after the incident ID; compiled backends mirror the sigma directory
// structure so we can extract incident IDs the same way.
func backfillDetectionRules(
	modName string,
	incidents []*incident.Incident,
	sigmaRoot string,
	be []backends.Backend,
	rootFor func(string) string,
	includeYARA bool,
) {
	if len(incidents) == 0 {
		return
	}

	// Build set of known incident IDs for fast prefix matching.
	knownIDs := make(map[string]*incident.Incident, len(incidents))
	for _, inc := range incidents {
		if inc.ID != "" {
			knownIDs[inc.ID] = inc
			// Clear existing DetectionRules so this pass is idempotent.
			inc.DetectionRules = nil
		}
	}

	// scanDir walks a rule directory and adds DetectionRule entries to each
	// matched incident. dirRoot is stripped from file paths to produce the
	// module-relative path stored in DetectionRule.Path.
	scanDir := func(dir, backend, dirRoot string) {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			// Extract incident ID from filename. Rule filenames are always
			// "{incident-id}-{rule-slug}.ext". IDs have the form
			// "dragnet-{module}-{year}-{N}" (4+ dash-separated components).
			// Try candidate prefixes from longest to shortest rather than
			// scanning all knownIDs — O(depth) instead of O(N incidents).
			base := strings.TrimSuffix(d.Name(), filepath.Ext(d.Name()))
			parts := strings.Split(base, "-")
			var matchedInc *incident.Incident
			for n := len(parts); n >= 4; n-- {
				if inc, ok := knownIDs[strings.Join(parts[:n], "-")]; ok {
					matchedInc = inc
					break
				}
			}
			if matchedInc == nil {
				return nil
			}

			// Derive layer from path: {dir}/{layer}/{year}/{file}
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				rel = base
			}
			relParts := strings.SplitN(rel, string(filepath.Separator), 3)
			layer := ""
			if len(relParts) >= 2 {
				layer = relParts[0]
			}

			// Path relative to module root in the satellite repo.
			modulePath, _ := filepath.Rel(dirRoot, path)

			matchedInc.DetectionRules = append(matchedInc.DetectionRules, incident.DetectionRule{
				Backend: backend,
				Layer:   layer,
				Path:    filepath.ToSlash(modulePath),
			})
			return nil
		})
	}

	// Sigma source.
	// sigmaRoot = {satellite}/{module}/rules/sigma — module root is two levels up.
	sigmaModuleRoot := filepath.Dir(filepath.Dir(sigmaRoot)) // {satellite}/{module}
	scanDir(sigmaRoot, "sigma", sigmaModuleRoot)

	// Compiled backends.
	for _, b := range be {
		root := rootFor(b.Name())
		compiledDir := filepath.Join(root, "rules", b.Name())
		if _, err := os.Stat(compiledDir); err == nil {
			scanDir(compiledDir, b.Name(), root)
		}
	}

	// IOC-native (YARA).
	if includeYARA {
		root := rootFor("yara")
		yaraDir := filepath.Join(root, "rules", "yara")
		if _, err := os.Stat(yaraDir); err == nil {
			scanDir(yaraDir, "yara", root)
		}
	}

	total := 0
	for _, inc := range incidents {
		total += len(inc.DetectionRules)
	}
	log.Printf("[generate][%s] detection_rules: %d rule refs across %d incidents", modName, total, len(incidents))
}

// extractIncidentID returns the incident ID from the "Incident: <id>" line
// embedded in a sigma rule's description by the sigma generator, or "" if
// the tag is absent. Matches the same convention used by doctor's rules-ref check.
func extractIncidentID(data []byte) string {
	const tag = "Incident: "
	idx := strings.Index(string(data), tag)
	if idx < 0 {
		return ""
	}
	rest := string(data)[idx+len(tag):]
	end := strings.IndexAny(rest, " \t\n\r")
	if end < 0 {
		end = len(rest)
	}
	return strings.TrimSpace(rest[:end])
}

func sanitizeFilename(id string) string {
	var sb strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	return sb.String()
}
