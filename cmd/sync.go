package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/dragnet-dev/dragnet/internal/actor"
	"github.com/dragnet-dev/dragnet/internal/config"
	"github.com/dragnet-dev/dragnet/internal/container"
	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/dragnet-dev/dragnet/internal/index"
	"github.com/dragnet-dev/dragnet/internal/ioc"
	"github.com/dragnet-dev/dragnet/internal/popularity"
	"github.com/dragnet-dev/dragnet/internal/sigma"
	"github.com/dragnet-dev/dragnet/internal/sources"
	"github.com/dragnet-dev/dragnet/internal/sources/mitre"
	"github.com/dragnet-dev/dragnet/internal/sources/multidomain"
	"github.com/dragnet-dev/dragnet/internal/sources/osv"
	"github.com/dragnet-dev/dragnet/internal/state"
	"github.com/dragnet-dev/dragnet/internal/stix"
	"github.com/dragnet-dev/dragnet/internal/typosquat"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// perSourceFetchTimeout caps each source's individual Fetch() call. Used to
// build the per-source context, but several sources have local processing
// loops that don't honour ctx.Done(); allSourcesDeadline below is the hard
// safety net for those.
// perSourceFetchTimeout was bumped from 90s to 150s once NVD's 2-year
// paginated backfill landed: ~6 windows × up to 4 pages × ~1.5s req +
// 1s pause = comfortably ~50s steady-state, but first-run / slow days
// can push past 90s and lose all NVD data. 150s gives headroom without
// being absurd; the allSourcesDeadline (5 min) still caps the module.
const perSourceFetchTimeout = 150 * time.Second

// allSourcesDeadline is the absolute wall-clock budget for the parallel-fetch
// stage of one module. After this, the wg.Wait() bails out, abandons any
// still-running goroutines, and proceeds with whatever was collected.
const allSourcesDeadline = 5 * time.Minute

// fetchHeartbeatInterval controls how often we log "still waiting on these
// sources" while wg.Wait blocks. Critical for CI runs where the only signal
// of progress is stderr.
const fetchHeartbeatInterval = 30 * time.Second

// hardWallClockBudget is an absolute escape hatch for the entire sync command.
// If something goes really sideways and even allSourcesDeadline doesn't fire
// (suspected runtime starvation under heavy GC pressure on the prior haul
// run), this watchdog os.Exit()s to make sure CI never burns the full 6h
// runner budget.
// 30 min covers a worst-case container module run on a fresh CI runner:
// Trivy DB download (~1 min) + 165k incident merge/persist (~30s) +
// sigma generation for the ~7k Tier-1/2/3 records (~17 min). Workflow
// timeout in haul/sync.yml is 90 min — well outside this hard escape hatch.
const hardWallClockBudget = 30 * time.Minute

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Poll intelligence sources and update rules for one or all modules",
	RunE:  runSync,
}

var (
	syncModule     string
	syncSources    string
	syncEcosystems string
	syncSince      string
	syncDryRun     bool
	syncBackfill   bool
)

func init() {
	syncCmd.Flags().StringVar(&syncModule, "module", "all",
		"Module to sync: supply|malware|ransomware|cve|all")
	syncCmd.Flags().StringVar(&syncSources, "sources", "",
		"Comma-separated sources to poll (default: from dragnet.yaml)")
	syncCmd.Flags().StringVar(&syncEcosystems, "ecosystems", "",
		"Comma-separated ecosystems to include (default: from dragnet.yaml)")
	syncCmd.Flags().StringVar(&syncSince, "since", "",
		"Override last sync timestamp (ISO8601)")
	syncCmd.Flags().BoolVar(&syncDryRun, "dry-run", false,
		"Print actions without committing changes")
	syncCmd.Flags().BoolVar(&syncBackfill, "backfill", false,
		"Fetch all available historical data. Sets --since 2020-01-01. Skips registry sources.")
}

// backfillSkip lists registry sources excluded during --backfill to avoid re-polling high-volume feeds.
var backfillSkip = map[string]bool{
	"npm_registry": true, "pypi": true, "cargo": true,
	"maven": true, "nuget": true, "rubygems": true,
	"go_modules": true, "hex": true, "packagist": true, "pub": true,
}

func runSync(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}

	moduleNames := resolveModules(syncModule)

	stateMgr := state.New()
	st, err := stateMgr.Load(filepath.Join(dataDir(), "state/last_sync.json"))
	if err != nil {
		return err
	}

	// Parse --since override once (applies to all modules when set).
	var sinceOverride *time.Time
	if syncSince != "" {
		t, err := time.Parse(time.RFC3339, syncSince)
		if err != nil {
			return err
		}
		sinceOverride = &t
	}
	if syncBackfill && sinceOverride == nil {
		t := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		sinceOverride = &t
		log.Printf("[backfill] since defaulting to %s", t.Format(time.RFC3339))
	}

	// Load popular packages for typosquat detection (supply module).
	popularByEco := map[string][]popularity.PopularPackage{}
	if modCfg, ok := cfg.Modules["supply"]; ok {
		for _, eco := range modCfg.Ecosystems {
			pkgs, err := popularity.LoadPopularList(filepath.Join(dataDir(), "state/popular_packages"), eco)
			if err != nil {
				log.Printf("[sync] popular list %s: %v (typosquat detection disabled for this ecosystem)", eco, err)
				continue
			}
			popularByEco[eco] = pkgs
		}
	}

	// Load popular images for container tier filtering.
	var popularImages []container.PopularImage
	if imagesPath := filepath.Join(dataDir(), "state/popular_images.json"); fileExists(imagesPath) {
		imgs, err := container.LoadPopularImages(imagesPath)
		if err != nil {
			log.Printf("[sync] popular images load: %v (container tier filter disabled)", err)
		} else {
			popularImages = imgs
		}
	}

	// Graceful cancellation on SIGINT.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Watchdog: hard os.Exit if the entire sync hasn't completed within
	// hardWallClockBudget. This is the absolute escape hatch when the
	// per-source ctx, the allSourcesDeadline, and the heartbeat all somehow
	// fail to bail us out — observed once on the first haul sync where the
	// engine produced no output for 30min before the workflow killed it.
	syncDoneWatchdog := make(chan struct{})
	defer close(syncDoneWatchdog)
	go func() {
		select {
		case <-syncDoneWatchdog:
			return
		case <-time.After(hardWallClockBudget):
			log.Printf("[sync] HARD WATCHDOG: %s elapsed without completion, forcing exit", hardWallClockBudget)
			os.Exit(2)
		}
	}()

	iocExp := ioc.New()

	// ATT&CK actor store — fetched once, used by all modules for attribution.
	// Falls back to on-disk profiles when the bundle hasn't changed (ETag match).
	actorStore, newMITREETag := loadActorStore(ctx, st.MITREETag)
	if newMITREETag != "" {
		st.MITREETag = newMITREETag
	}
	if actorStore != nil {
		stix.SetActorStore(actorStore)
	}

	// Per-module source polling.
	moduleIncidents := map[string][]*incident.Incident{}
	moduleFetchErrors := map[string]int32{} // non-zero means at least one source failed

	for _, modName := range moduleNames {
		modCfg, ok := cfg.Modules[modName]
		if !ok {
			return fmt.Errorf("unknown module %q", modName)
		}

		// Resolve the since timestamp for this module.
		// Priority: explicit --since > per-module cursor > zero (first-run bulk).
		//
		// We deliberately do NOT fall back to st.LastSync here. The previous
		// fallback caused cross-pollution between modules when they were run
		// back-to-back in the same workflow: sync supply would set the global
		// cursor to now, then sync malware would inherit it and fetch nothing.
		// Per-module cursors are per-module; a brand-new module should start
		// with a full backfill, not silently inherit another module's cursor.
		var since time.Time
		if sinceOverride != nil {
			since = *sinceOverride
		} else if src := st.Sources[modName]; src.LastSync != nil {
			since = *src.LastSync
		}

		var srcs []sources.Source
		switch {
		case syncSources == "all":
			srcs = sources.All()
		case syncSources != "":
			var err error
			srcs, err = sources.ByName(strings.Split(syncSources, ","))
			if err != nil {
				return err
			}
		default:
			var err error
			srcs, err = sources.ForModule(modCfg.Sources)
			if err != nil {
				return err
			}
		}

		if syncBackfill {
			var filtered []sources.Source
			for _, s := range srcs {
				if !backfillSkip[s.Name()] {
					filtered = append(filtered, s)
				}
			}
			srcs = filtered
		}

		var (
			mu            sync.Mutex
			incidents     []*incident.Incident
			fetchErrCount int32
			wg            sync.WaitGroup
			pending       sync.Map // src.Name() -> startTime for any source still running
			// Per-source results captured so we can print a single-line health
			// summary at the end of the module. Without it, silent failures
			// (source returns 0 with no error) are buried in 100s of log lines.
			srcStats sync.Map // src.Name() -> srcResult
		)
		sem := make(chan struct{}, 10)
		for _, src := range srcs {
			wg.Add(1)
			go func(s sources.Source) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				start := time.Now()
				pending.Store(s.Name(), start)
				defer pending.Delete(s.Name())
				log.Printf("[sync][%s] fetching %s since %s", modName, s.Name(), since.Format(time.RFC3339))
				fetchCtx, fetchCancel := context.WithTimeout(ctx, perSourceFetchTimeout)
				got, err := s.Fetch(fetchCtx, since)
				fetchCancel()
				dur := time.Since(start).Round(time.Millisecond)
				if err != nil {
					log.Printf("[sync][%s] %s: %v (skipping after %s)", modName, s.Name(), err, dur)
					atomic.AddInt32(&fetchErrCount, 1)
					srcStats.Store(s.Name(), srcResult{count: 0, err: err.Error()})
					return
				}
				log.Printf("[sync][%s] %s: fetched %d incidents in %s", modName, s.Name(), len(got), dur)
				srcStats.Store(s.Name(), srcResult{count: len(got)})
				mu.Lock()
				incidents = append(incidents, got...)
				mu.Unlock()
			}(src)
		}

		// Wait for fetches with three layers of safety:
		//   1. heartbeat — log every 30s which sources are still running so a
		//      stuck run is visible from CI logs immediately, not on cancel.
		//   2. allSourcesDeadline — bail out at 5min, abandon stuck goroutines.
		//   3. hardWallClockBudget watchdog (separate goroutine started above)
		//      os.Exit()s the whole binary at 20min, regardless.
		// Layer 2 alone proved unreliable on the first haul sync (silence for
		// 30min before the workflow killed it) — possibly runtime starvation
		// under heavy GC after big slice appends.
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		heartbeat := time.NewTicker(fetchHeartbeatInterval)
		deadline := time.After(allSourcesDeadline)
	waitLoop:
		for {
			select {
			case <-done:
				heartbeat.Stop()
				break waitLoop
			case <-deadline:
				heartbeat.Stop()
				var stuck []string
				now := time.Now()
				pending.Range(func(k, v any) bool {
					stuck = append(stuck, fmt.Sprintf("%s(%s)", k.(string), now.Sub(v.(time.Time)).Round(time.Second)))
					return true
				})
				log.Printf("[sync][%s] hit %s deadline; abandoning %d source(s) still running: %s",
					modName, allSourcesDeadline, len(stuck), strings.Join(stuck, ", "))
				atomic.AddInt32(&fetchErrCount, int32(len(stuck)))
				break waitLoop
			case <-heartbeat.C:
				var pendingNames []string
				now := time.Now()
				pending.Range(func(k, v any) bool {
					pendingNames = append(pendingNames, fmt.Sprintf("%s(%s)", k.(string), now.Sub(v.(time.Time)).Round(time.Second)))
					return true
				})
				log.Printf("[sync][%s] heartbeat: %d source(s) still running: %s",
					modName, len(pendingNames), strings.Join(pendingNames, ", "))
			}
		}

		// Source-health summary: a single line that makes silent zero-return
		// failures visible without grepping the per-source lines above.
		logSourceHealth(modName, &srcStats)

		// OSV package enrichment for the supply module.
		//
		// IMPORTANT: skip when the bulk OSV path was taken (since > 7 days).
		// Bulk export already returned every OSV advisory; enriching would
		// then issue thousands of additional /querybatch HTTP calls in series
		// for duplicate data and burn 5-20+ minutes silently. The bulk cutoff
		// here mirrors osv.bulkCutoff inside the OSV client.
		const osvBulkCutoff = 7 * 24 * time.Hour
		if modName == "supply" && time.Since(since) <= osvBulkCutoff {
			var pkgsToEnrich []incident.Package
			seen := map[string]bool{}
			for _, inc := range incidents {
				for _, pkg := range inc.Packages {
					key := pkg.Ecosystem + "/" + pkg.Name + "@" + strings.Join(pkg.AffectedVersions, ",")
					if !seen[key] {
						seen[key] = true
						pkgsToEnrich = append(pkgsToEnrich, pkg)
					}
				}
			}
			if len(pkgsToEnrich) > 0 {
				log.Printf("[sync][%s] osv enrich: starting with %d unique packages", modName, len(pkgsToEnrich))
				osvClient := osv.New()
				enrichStart := time.Now()
				enriched, err := osvClient.EnrichPackages(ctx, pkgsToEnrich)
				if err != nil {
					log.Printf("[sync][%s] osv enrich: %v (skipping after %s)", modName, err, time.Since(enrichStart).Round(time.Second))
				} else if len(enriched) > 0 {
					log.Printf("[sync][%s] osv enrich: %d additional advisories in %s", modName, len(enriched), time.Since(enrichStart).Round(time.Second))
					incidents = append(incidents, enriched...)
				}
			}
		} else if modName == "supply" {
			log.Printf("[sync][%s] osv enrich: skipped (bulk fetch already included full advisory set)", modName)
		}

		// Supply enrichment is now local-only (no HTTP calls — uses the
		// popular-packages snapshot in popularByEco), so it's safe even for
		// the bulk path's 264k+ incidents.
		if modName == "supply" {
			log.Printf("[sync][%s] enrichSupplyIncidents: %d incidents", modName, len(incidents))
			stepStart := time.Now()
			incidents = enrichSupplyIncidents(ctx, incidents, popularByEco)
			log.Printf("[sync][%s] enrichSupplyIncidents: done in %s", modName, time.Since(stepStart).Round(time.Second))
		}

		if modName == "container" {
			incidents = enrichContainerIncidents(incidents, popularImages, cfg.Modules["container"])
		}

		// MergeAll uses union-find bucketing by every package/campaign/IOC key,
		// so it's near-linear even on the 490k bulk-load case. No skip needed.
		log.Printf("[sync][%s] MergeAll: merging %d incidents", modName, len(incidents))
		mergeStart := time.Now()
		incidents = incident.MergeAll(incidents)
		log.Printf("[sync][%s] MergeAll: done in %s (%d after merge)", modName, time.Since(mergeStart).Round(time.Second), len(incidents))

		// Actor attribution — O(incidents × actors), ~5s for 490k × 174.
		if actorStore != nil {
			attrStart := time.Now()
			incidents = actor.Attribute(incidents, actorStore, modName)
			log.Printf("[sync][%s] actor.Attribute: done in %s", modName, time.Since(attrStart).Round(time.Second))
		}

		// Persist the full merged incident set as the authoritative haul data:
		//   {module}/incidents/all/{shard}.jsonl   — every incident, sharded by ID prefix
		//   {module}/incidents/index.json          — curated subset for port's listing
		//   {module}/lookup/by-package.json        — ecosystem/name -> incidents lookup
		// port/buoy/scope/trawl all consume these. Generate's STIX/sigma compilation
		// reads all.jsonl when on-disk YAMLs are absent.
		if !syncDryRun {
			persistStart := time.Now()
			if err := index.WriteAllJSONLShards(incidents, modCfg.OutputDir); err != nil {
				log.Printf("[sync][%s] persist all.jsonl: %v", modName, err)
			}
			if err := index.WriteByPackageLookup(incidents, modCfg.OutputDir); err != nil {
				log.Printf("[sync][%s] persist by-package: %v", modName, err)
			}
			if err := index.WriteCuratedIndex(modName, incidents, modCfg.OutputDir); err != nil {
				log.Printf("[sync][%s] persist index.json: %v", modName, err)
			}
			log.Printf("[sync][%s] persist: done in %s", modName, time.Since(persistStart).Round(time.Second))
		}

		moduleIncidents[modName] = incidents
		moduleFetchErrors[modName] = atomic.LoadInt32(&fetchErrCount)
	}

	// Multi-domain source routing — fetched once, routed to matching modules.
	// Blog posts with no IOCs are written as draft YAMLs for human triage rather than
	// fed into the Sigma generator (they produce empty rules with no detection criteria).
	moduleDrafts := map[string][]*incident.Incident{}
	if len(cfg.MultiDomainSources) > 0 {
		// Resolve since for multi-domain — mirrors per-module priority chain.
		var mdSince time.Time
		if sinceOverride != nil {
			mdSince = *sinceOverride
		} else if src := st.Sources["__multidomain__"]; src.LastSync != nil {
			mdSince = *src.LastSync
		} else {
			mdSince = st.LastSync
		}

		for name, mdCfg := range cfg.MultiDomainSources {
			fetcher := multidomain.GetFetcher(name)
			if fetcher == nil {
				log.Printf("[sync] no fetcher registered for multi-domain source %q", name)
				continue
			}
			log.Printf("[sync] fetching multi-domain source %s since %s", name, mdSince.Format(time.RFC3339))
			mdCtx, mdCancel := context.WithTimeout(ctx, 2*time.Minute)
			posts, err := fetcher.FetchPosts(mdCtx, mdSince)
			mdCancel()
			if err != nil {
				log.Printf("[sync] %s: %v (skipping)", name, err)
				continue
			}
			router := multidomain.New(mdCfg)
			for _, post := range posts {
				for _, modName := range router.Route(post) {
					inc := convertPostToIncident(post, modName, name)
					moduleDrafts[modName] = append(moduleDrafts[modName], inc)
					log.Printf("[sync][%s] routed %s post: %s", modName, name, post.Title)
				}
			}
		}

		// Persist multi-domain cursor so reruns don't re-fetch already-processed posts.
		if !syncDryRun && sinceOverride == nil {
			now := time.Now().UTC()
			if st.Sources == nil {
				st.Sources = make(map[string]state.SourceState)
			}
			src := st.Sources["__multidomain__"]
			src.LastSync = &now
			st.Sources["__multidomain__"] = src
			if err := stateMgr.Save(filepath.Join(dataDir(), "state/last_sync.json"), st); err != nil {
				log.Printf("[sync][multidomain] save state: %v", err)
			}
		}
	}

	// Load the shared Dragnet ID registry (assigns sequential dragnet-<module>-<year>-<NNNN> IDs).
	sigmaReg, regErr := sigma.LoadRegistry(filepath.Join(dataDir(), "state/sigma-id-registry.json"))
	if regErr != nil {
		log.Printf("[sync] sigma registry load failed (starting fresh): %v", regErr)
		sigmaReg, _ = sigma.LoadRegistry("/dev/null") // guaranteed empty
	}

	// Generate rules + export IOCs per module.
	for _, modName := range moduleNames {
		incidents := moduleIncidents[modName]
		modCfg, ok := cfg.Modules[modName]
		if !ok {
			continue
		}

		sigmaOutDir := filepath.Join(modCfg.OutputDir, "rules", "sigma")
		feedsDir := filepath.Join(modCfg.OutputDir, "feeds")
		// Wipe stale Sigma files only on --backfill (full historical re-ingestion).
		// Incremental syncs fetch a time-window of incidents and must not wipe
		// rules generated from earlier windows — those incidents aren't re-fetched.
		if !syncDryRun && syncBackfill {
			_ = os.RemoveAll(sigmaOutDir)
		}
		gen := sigma.New(sigmaOutDir, modName, sigmaReg)

		genStart := time.Now()
		log.Printf("[sync][%s] generating rules + IOC feeds for %d incidents", modName, len(incidents))
		skippedTier4 := 0
		for i, inc := range incidents {
			// Progress every 20k for the bulk case (264k OSV advisories).
			if i > 0 && i%20_000 == 0 {
				log.Printf("[sync][%s] generate progress: %d/%d (%s elapsed)", modName, i, len(incidents), time.Since(genStart).Round(time.Second))
			}
			if syncDryRun {
				log.Printf("[sync][%s] dry-run: would generate rules for %s", modName, inc.ID)
				continue
			}
			// Skip sigma rule generation AND IOC export for Tier 4
			// (informational) container records. The bulk Trivy DB (~165k
			// CVEs) lands in this tier when no popular-images snapshot is
			// configured; doing per-incident sigma + IOC export for all of
			// them dominates the workflow runtime (~20 min). They still land
			// in incidents/all/*.jsonl for cross-reference — they just don't
			// ship as actionable detection rules or get listed in the
			// IOC feeds.
			if inc.ContainerExt != nil && inc.ContainerExt.Tier == 4 {
				skippedTier4++
				continue
			}
			if err := gen.Generate(inc); err != nil {
				log.Printf("[sync][%s] generate %s: %v", modName, inc.ID, err)
			}
			if inc.ContainerExt != nil {
				if err := iocExp.ExportContainerImages(inc, feedsDir); err != nil {
					log.Printf("[sync][%s] container export %s: %v", modName, inc.ID, err)
				}
			} else {
				if err := iocExp.Export(inc, feedsDir); err != nil {
					log.Printf("[sync][%s] ioc export %s: %v", modName, inc.ID, err)
				}
			}
		}
		if skippedTier4 > 0 {
			log.Printf("[sync][%s] skipped sigma+IOC for %d Tier-4 informational records", modName, skippedTier4)
		}
		log.Printf("[sync][%s] generate: done in %s", modName, time.Since(genStart).Round(time.Second))

		// Write multi-domain blog posts as draft YAMLs for human triage.
		// Only write drafts that have at least one technical signal — packages,
		// network IOCs, file hashes, or file names. Posts with no signals are
		// vendor marketing or general news; they will never yield actionable intel.
		if drafts := moduleDrafts[modName]; len(drafts) > 0 {
			var signalDrafts []*incident.Incident
			for _, d := range drafts {
				ind := d.Indicators
				hasSignal := len(d.Packages) > 0 ||
					len(ind.Domains) > 0 ||
					len(ind.IPs) > 0 ||
					len(ind.URLs) > 0 ||
					len(ind.FileHashes) > 0 ||
					len(ind.FileNames) > 0 ||
					len(ind.FilePaths) > 0 ||
					ind.GitIndicators != nil ||
					ind.CredentialTargets != nil
				if hasSignal {
					signalDrafts = append(signalDrafts, d)
				}
			}
			if len(signalDrafts) > 0 {
				draftsDir := filepath.Join(modCfg.OutputDir, "incidents", "drafts")
				if err := writeDraftIncidents(draftsDir, signalDrafts, syncDryRun, modName); err != nil {
					log.Printf("[sync][%s] write drafts: %v", modName, err)
				}
			}
		}

		// Persist per-module cursor so subsequent module runs aren't skipped.
		// Skip if any source returned an error — the window may be incomplete and
		// re-fetching from the old cursor on the next run is safer than skipping it.
		if !syncDryRun && sinceOverride == nil && moduleFetchErrors[modName] == 0 {
			now := time.Now().UTC()
			if st.Sources == nil {
				st.Sources = make(map[string]state.SourceState)
			}
			src := st.Sources[modName]
			src.LastSync = &now
			st.Sources[modName] = src
			if err := stateMgr.Save(filepath.Join(dataDir(), "state/last_sync.json"), st); err != nil {
				log.Printf("[sync][%s] save state: %v", modName, err)
			}
		}
	}

	// Save the Dragnet ID registry so sequential IDs persist across syncs.
	if !syncDryRun {
		if err := sigmaReg.Save(); err != nil {
			log.Printf("[sync] sigma registry save: %v", err)
		}
	}

	if syncDryRun {
		log.Printf("[sync] dry-run complete — no state updated")
		return nil
	}

	// Write actor profiles after all modules are attributed.
	if actorStore != nil {
		if err := actorStore.WriteProfiles(filepath.Join(dataDir(), "actors/profiles")); err != nil {
			log.Printf("[sync] write actor profiles: %v", err)
		} else {
			withIncidents := 0
			for _, p := range actorStore.Profiles() {
				if len(p.LinkedIncidents) > 0 {
					withIncidents++
				}
			}
			log.Printf("[sync] actor profiles: %d total, %d with linked incidents",
				len(actorStore.Profiles()), withIncidents)
		}
	}

	// Note: we don't touch st.LastSync here. It exists for backwards
	// compatibility with state files written by older versions, but new
	// state writes only update the per-module cursor in st.Sources (see
	// the per-module save above). Cross-module fallback caused supply →
	// malware silent-zero on first runs.
	return stateMgr.Save(filepath.Join(dataDir(), "state/last_sync.json"), st)
}

// loadActorStore fetches the MITRE ATT&CK bundle (ETag-cached) and returns an
// actor store. Falls back to on-disk profiles when the bundle is unchanged.
// Returns (store, newETag) — newETag is empty when no download occurred.
// srcResult is the per-source outcome captured during the parallel fetch loop.
type srcResult struct {
	count int
	err   string // empty when the fetch succeeded
}

// logSourceHealth emits one summary line per module: how many sources were OK,
// how many returned zero records, and how many errored. Silent failures are the
// most expensive failure mode in this pipeline (a source quietly returns 0 and
// the module empties out); this is the line that surfaces them at a glance.
func logSourceHealth(modName string, srcStats *sync.Map) {
	type entry struct {
		name string
		r    srcResult
	}
	var rows []entry
	srcStats.Range(func(k, v any) bool {
		rows = append(rows, entry{name: k.(string), r: v.(srcResult)})
		return true
	})
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })

	var ok, empty, errored []string
	for _, e := range rows {
		switch {
		case e.r.err != "":
			errored = append(errored, e.name)
		case e.r.count == 0:
			empty = append(empty, e.name)
		default:
			ok = append(ok, fmt.Sprintf("%s(%d)", e.name, e.r.count))
		}
	}
	log.Printf("[sync][%s] source health: %d OK / %d empty / %d errored", modName, len(ok), len(empty), len(errored))
	if len(ok) > 0 {
		log.Printf("[sync][%s]   ok:      %s", modName, strings.Join(ok, ", "))
	}
	if len(empty) > 0 {
		log.Printf("[sync][%s]   empty:   %s", modName, strings.Join(empty, ", "))
	}
	if len(errored) > 0 {
		log.Printf("[sync][%s]   errored: %s", modName, strings.Join(errored, ", "))
	}
}

func loadActorStore(ctx context.Context, lastETag string) (*actor.Store, string) {
	profiles, newETag, err := mitre.New().FetchActors(ctx, lastETag)
	if err != nil {
		log.Printf("[sync] mitre: %v — loading on-disk actor profiles", err)
		store, _ := actor.ReadProfiles(filepath.Join(dataDir(), "actors/profiles"))
		return store, ""
	}
	if len(profiles) == 0 {
		// ETag matched — no change, load from disk.
		store, _ := actor.ReadProfiles(filepath.Join(dataDir(), "actors/profiles"))
		// If disk is empty (e.g. actors/ was wiped), the ETag is stale — re-fetch.
		if len(store.Profiles()) == 0 {
			log.Printf("[sync] mitre: disk profiles missing despite ETag match — forcing re-fetch")
			profiles, newETag, err = mitre.New().FetchActors(ctx, "")
			if err != nil {
				log.Printf("[sync] mitre: re-fetch failed: %v", err)
				return store, ""
			}
			if len(profiles) > 0 {
				log.Printf("[sync] mitre: loaded %d actor profiles from ATT&CK bundle (re-fetch)", len(profiles))
				return actor.Load(profiles), newETag
			}
		}
		return store, newETag
	}
	log.Printf("[sync] mitre: loaded %d actor profiles from ATT&CK bundle", len(profiles))
	return actor.Load(profiles), newETag
}

// writeDraftIncidents marshals draft incidents to YAML files in draftsDir.
func writeDraftIncidents(draftsDir string, drafts []*incident.Incident, dryRun bool, modName string) error {
	if dryRun {
		for _, d := range drafts {
			log.Printf("[sync][%s] dry-run: would write draft %s", modName, d.ID)
		}
		return nil
	}
	if err := os.MkdirAll(draftsDir, 0o755); err != nil {
		return err
	}
	for _, d := range drafts {
		path := filepath.Join(draftsDir, d.ID+".yaml")
		if _, err := os.Stat(path); err == nil {
			continue // already exists — don't overwrite a previously triaged draft
		}
		data, err := yaml.Marshal(d)
		if err != nil {
			log.Printf("[sync][%s] marshal draft %s: %v", modName, d.ID, err)
			continue
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			log.Printf("[sync][%s] write draft %s: %v", modName, d.ID, err)
		}
	}
	return nil
}

// enrichSupplyIncidents runs typosquat detection and impact scoring on supply chain incidents.
//
// Impact scoring uses the locally-loaded popular-packages snapshot
// (state/popular_packages/{ecosystem}.json) rather than firing one HTTP call
// per package per incident. The old code burned ~500k registry requests on
// the first run (264k incidents × ~2 pkgs each), risking IP-level rate
// limiting on npm/pypi. Long-tail packages not in the popular list contribute
// no impact data — by construction those have low download counts and
// low impact, which is exactly what we'd report anyway.
func enrichSupplyIncidents(ctx context.Context, incidents []*incident.Incident, popularByEco map[string][]popularity.PopularPackage) []*incident.Incident {
	const typosquatThreshold = 0.80

	// Build a per-ecosystem name→PopularPackage map once so impact lookups
	// are O(1) instead of O(n) over the popular slice.
	popularIdx := make(map[string]map[string]popularity.PopularPackage, len(popularByEco))
	for eco, pkgs := range popularByEco {
		m := make(map[string]popularity.PopularPackage, len(pkgs))
		for _, p := range pkgs {
			m[p.Name] = p
		}
		popularIdx[eco] = m
	}

	_ = ctx // formerly used by FetchDownloads; kept on signature for compatibility

	for _, inc := range incidents {
		for _, pkg := range inc.Packages {
			popular, ok := popularByEco[pkg.Ecosystem]
			if !ok || len(popular) == 0 {
				continue
			}

			// Typosquat detection.
			if match := typosquat.Detect(pkg.Name, popular, typosquatThreshold); match != nil {
				inc.AttackType = "typosquat"
				inc.TyposquatInfo = &incident.TyposquatDetails{
					NewPackage:            match.NewPackage,
					TargetPackage:         match.TargetPackage,
					TargetWeeklyDownloads: match.TargetDownloads,
					TargetImpactRating:    match.TargetImpact,
					SimilarityScore:       match.SimilarityScore,
					Technique:             match.Technique,
				}
				// Typosquat severity uses the target package's impact.
				inc.Severity = impactToSeverity(match.TargetImpact)
				log.Printf("[sync][supply] typosquat detected: %s → %s (%.2f, %s)",
					match.NewPackage, match.TargetPackage, match.SimilarityScore, match.Technique)
			}
		}

		// Impact scoring — local lookup only, no HTTP. Packages not in the
		// popular snapshot get no entry (treated as low-impact long-tail).
		var (
			packageImpacts []incident.PackageImpact
			totalWeekly    int64
		)
		for _, pkg := range inc.Packages {
			eco, ok := popularIdx[pkg.Ecosystem]
			if !ok {
				continue
			}
			hit, ok := eco[pkg.Name]
			if !ok {
				continue
			}
			packageImpacts = append(packageImpacts, incident.PackageImpact{
				Name:             pkg.Name,
				Ecosystem:        pkg.Ecosystem,
				WeeklyDownloads:  hit.WeeklyDownloads,
				MonthlyDownloads: 0, // not in the popular snapshot; weekly is what matters for impact rating
				ImpactRating:     hit.ImpactRating,
			})
			totalWeekly += hit.WeeklyDownloads
		}

		if len(packageImpacts) > 0 {
			overallRating := string(popularity.ComputeImpactRating(topWeekly(packageImpacts)))
			targetImpact := ""
			if inc.TyposquatInfo != nil {
				targetImpact = inc.TyposquatInfo.TargetImpactRating
			}
			inc.Impact = &incident.IncidentImpact{
				Packages:              packageImpacts,
				OverallImpactRating:   overallRating,
				TotalWeeklyDownloads:  totalWeekly,
				TyposquatTargetImpact: targetImpact,
			}
			// Boost severity for critical-impact supply chain incidents.
			if overallRating == "critical" && inc.Severity != "critical" && inc.AttackType != "typosquat" {
				inc.Severity = "critical"
			}
		}
	}
	return incidents
}

func topWeekly(pkgs []incident.PackageImpact) int64 {
	var max int64
	for _, p := range pkgs {
		if p.WeeklyDownloads > max {
			max = p.WeeklyDownloads
		}
	}
	return max
}

func impactToSeverity(impact string) string {
	switch impact {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

// convertPostToIncident creates a draft incident from a multi-domain blog post.
func convertPostToIncident(post multidomain.BlogPost, module, sourceName string) *incident.Incident {
	id := fmt.Sprintf("%s-draft-%s-%s", module, sanitizeID(sourceName), sanitizeID(post.Title))
	if len(id) > 80 {
		id = id[:80]
	}
	desc := post.Title
	if post.Description != "" && len(post.Description) < 300 {
		desc = post.Description
	}
	return &incident.Incident{
		ID:          id,
		Description: desc,
		AttackType:  "unknown",
		Severity:    "medium",
		References:  []string{post.Link},
	}
}

var reConsecutiveDashes = regexp.MustCompile(`-{2,}`)

func sanitizeID(s string) string {
	mapped := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		if r >= 'A' && r <= 'Z' {
			return unicode.ToLower(r)
		}
		return '-'
	}, s)
	return strings.Trim(reConsecutiveDashes.ReplaceAllString(mapped, "-"), "-")
}

// resolveModules expands "all" into the canonical module list.
func resolveModules(flag string) []string {
	if flag == "all" {
		return config.ModuleNames
	}
	return []string{flag}
}

// enrichContainerIncidents applies the three-tier CVE filter, dropping incidents
// that don't reach any tier. It also assigns the tier to ContainerExt.Tier so
// templates can reference it.
func enrichContainerIncidents(
	incidents []*incident.Incident,
	popularImages []container.PopularImage,
	modCfg config.ModuleConfig,
) []*incident.Incident {
	cfg := container.DefaultConfig()
	if modCfg.CVSSThresholds.Tier2 > 0 {
		cfg.Tier2CVSS = modCfg.CVSSThresholds.Tier2
	}
	if modCfg.CVSSThresholds.Tier3 > 0 {
		cfg.Tier3CVSS = modCfg.CVSSThresholds.Tier3
	}
	if modCfg.PopularImageThreshold > 0 {
		cfg.PopularImageThreshold = modCfg.PopularImageThreshold
	}

	var out []*incident.Incident
	for _, inc := range incidents {
		if inc.ContainerExt == nil {
			out = append(out, inc) // non-container incidents pass through
			continue
		}
		// EOL incidents always pass — they don't have a CVSS score.
		if inc.AttackType == "eol" {
			inc.ContainerExt.Tier = 2
			out = append(out, inc)
			continue
		}
		tier := container.Tier(
			inc.ContainerExt.CVSS,
			inc.ContainerExt.ExploitedInWild,
			inc.ContainerExt.PublicPoC,
			inc.ContainerExt.AffectedImages,
			popularImages,
			cfg,
		)
		if tier == 0 {
			// When no popular-images snapshot is configured we keep the
			// record as informational (Tier 4) rather than discarding it —
			// otherwise the entire ~165k Trivy DB drops silently before
			// haul ever sees it. Configure a snapshot via
			// `dragnet update-popular --module container` to enable strict
			// Tier 1/2/3 filtering.
			if len(popularImages) == 0 {
				inc.ContainerExt.Tier = 4
				out = append(out, inc)
			}
			continue
		}
		inc.ContainerExt.Tier = tier
		out = append(out, inc)
	}
	return out
}

// fileExists reports whether a file exists at path.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
