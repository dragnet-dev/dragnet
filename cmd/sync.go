package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
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
	syncAllowShrink bool
	syncRulesRoot   string
	syncSTIXRoot    string
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
	syncCmd.Flags().BoolVar(&syncAllowShrink, "allow-shrink", false,
		"Permit persist even when merged set is >50% smaller than prior on-disk count. "+
			"Required for legitimate purges; default refuses to prevent silent data loss.")
	syncCmd.Flags().StringVar(&syncRulesRoot, "rules-root", "",
		"Write per-incident sigma rules under {rules-root}/{module}/rules/... instead of inline. "+
			"v0.1.11 distribution split flag — mirrors `generate --rules-root` for the sync's "+
			"per-incident sigma generation path.")
	syncCmd.Flags().StringVar(&syncSTIXRoot, "stix-root", "",
		"Reserved for the distribution split. sync doesn't currently write STIX bundles "+
			"(generate handles that), so this flag is accepted for symmetry but unused today.")
}

// backfillSkip lists registry sources excluded during --backfill to avoid re-polling high-volume feeds.
var backfillSkip = map[string]bool{
	"npm_registry": true, "pypi": true, "cargo": true,
	"maven": true, "nuget": true, "rubygems": true,
	"go_modules": true, "hex": true, "packagist": true, "pub": true,
}

// SyncEngine holds the shared state that flows between phases of a sync run.
// runSync constructs one, initializes it, then calls phase methods in order.
type SyncEngine struct {
	cfg            *config.Config
	stateMgr       *state.Manager
	st             *state.State
	moduleNames    []string
	explicitModule bool
	sinceOverride  *time.Time
	popularByEco   map[string][]popularity.PopularPackage
	popularIdx     container.PopularIndex
	iocExp         *ioc.Exporter
	sigmaReg       *sigma.Registry
	actorStore     *actor.Store
	// Built up during per-module phases.
	moduleIncidents   map[string][]*incident.Incident
	moduleFetchErrors map[string]int32
	moduleDrafts      map[string][]*incident.Incident
}

func newSyncEngine() *SyncEngine {
	return &SyncEngine{
		moduleIncidents:   make(map[string][]*incident.Incident),
		moduleFetchErrors: make(map[string]int32),
		moduleDrafts:      make(map[string][]*incident.Incident),
	}
}

// loadConfig parses dragnet.yaml, resolves CLI flags, and loads sync state.
func (e *SyncEngine) loadConfig() error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}
	e.cfg = cfg
	e.moduleNames = resolveModules(syncModule)
	e.explicitModule = syncModule != "all"

	e.stateMgr = state.New()
	st, err := e.stateMgr.Load(filepath.Join(dataDir(), "state/last_sync.json"))
	if err != nil {
		return err
	}
	e.st = st

	if syncSince != "" {
		t, err := time.Parse(time.RFC3339, syncSince)
		if err != nil {
			return err
		}
		e.sinceOverride = &t
	}
	if syncBackfill && e.sinceOverride == nil {
		t := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		e.sinceOverride = &t
		log.Printf("[backfill] since defaulting to %s", t.Format(time.RFC3339))
	}
	return nil
}

// loadPopularData loads popular packages for typosquat detection and popular
// container images for container tier filtering.
func (e *SyncEngine) loadPopularData() {
	e.popularByEco = make(map[string][]popularity.PopularPackage)
	if modCfg, ok := e.cfg.Modules["supply"]; ok {
		for _, eco := range modCfg.Ecosystems {
			pkgs, err := popularity.LoadPopularList(filepath.Join(dataDir(), "state/popular_packages"), eco)
			if err != nil {
				log.Printf("[sync] popular list %s: %v (typosquat detection disabled for this ecosystem)", eco, err)
				continue
			}
			e.popularByEco[eco] = pkgs
		}
	}
	if imagesPath := filepath.Join(dataDir(), "state/popular_images.json"); fileExists(imagesPath) {
		imgs, err := container.LoadPopularImages(imagesPath)
		if err != nil {
			log.Printf("[sync] popular images load: %v (container tier filter disabled)", err)
		} else {
			e.popularIdx = container.BuildPopularIndex(imgs)
		}
	}
}

// initRegistries initializes the IOC exporter, sigma ID registry, and ATT&CK actor store.
func (e *SyncEngine) initRegistries(ctx context.Context) error {
	e.iocExp = ioc.New()

	// Load the shared Dragnet ID registry up front so we can assign canonical
	// dragnet-{module}-{year}-{seq} IDs at ingest time, not at sigma-gen time.
	sigmaReg, regErr := sigma.LoadRegistry(filepath.Join(dataDir(), "state/sigma-id-registry.json"))
	if regErr != nil {
		log.Printf("[sync] sigma registry load failed (starting fresh): %v", regErr)
		sigmaReg, _ = sigma.LoadRegistry("/dev/null")
	}
	e.sigmaReg = sigmaReg

	// Seed supply-chain actor profiles to disk (no-op if already present).
	if err := actor.SeedProfiles(filepath.Join(dataDir(), "actors/profiles")); err != nil {
		log.Printf("[sync] actor seed: %v", err)
	}

	// ATT&CK actor store — fetched once, ETag-cached, used by all modules.
	actorStore, newMITREETag := loadActorStore(ctx, e.st.MITREETag)
	if newMITREETag != "" {
		e.st.MITREETag = newMITREETag
	}
	if actorStore != nil {
		actor.ApplySeeds(actorStore)
		stix.SetActorStore(actorStore)
	}
	e.actorStore = actorStore
	return nil
}

// sinceFor returns the since timestamp for a module.
// Priority: explicit --since > per-module cursor > zero (first-run bulk).
// Deliberately does NOT fall back to st.LastSync — cross-module cursor
// inheritance caused supply→malware silent-zero on first runs.
func (e *SyncEngine) sinceFor(modName string) time.Time {
	if e.sinceOverride != nil {
		return *e.sinceOverride
	}
	if src := e.st.Sources[modName]; src.LastSync != nil {
		return *src.LastSync
	}
	return time.Time{}
}

// fetchModule runs the semaphore-bounded parallel source fetch for one module.
// Returns collected incidents and a count of source errors.
func (e *SyncEngine) fetchModule(ctx context.Context, modName string, modCfg config.ModuleConfig, since time.Time) ([]*incident.Incident, int32, error) {
	var srcs []sources.Source
	switch {
	case syncSources == "all":
		srcs = sources.All()
	case syncSources != "":
		var err error
		srcs, err = sources.ByName(strings.Split(syncSources, ","))
		if err != nil {
			return nil, 0, err
		}
	default:
		var err error
		srcs, err = sources.ForModule(modCfg.Sources)
		if err != nil {
			return nil, 0, err
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
			for _, inc := range got {
				if inc.Source == "" {
					inc.Source = s.Name()
				}
			}
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

	logSourceHealth(modName, &srcStats)
	return incidents, atomic.LoadInt32(&fetchErrCount), nil
}

// enrichModule applies all module-specific enrichment passes in order.
func (e *SyncEngine) enrichModule(ctx context.Context, modName string, since time.Time, modCfg config.ModuleConfig, incidents []*incident.Incident) []*incident.Incident {
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

	// Supply enrichment is local-only (typosquat detection + impact scoring).
	if modName == "supply" {
		log.Printf("[sync][%s] enrichSupplyIncidents: %d incidents", modName, len(incidents))
		stepStart := time.Now()
		incidents = enrichSupplyIncidents(ctx, incidents, e.popularByEco)
		log.Printf("[sync][%s] enrichSupplyIncidents: done in %s", modName, time.Since(stepStart).Round(time.Second))
	}
	if modName == "container" {
		incidents = enrichContainerIncidents(incidents, e.popularIdx, modCfg)
	}
	if modName == "cve" {
		before := len(incidents)
		incidents = filterCVEByQuality(incidents)
		log.Printf("[sync][%s] CVE quality filter: %d -> %d (kept KEV / CVSS>=9 / public PoC)", modName, before, len(incidents))
	}
	if modName == "os-packages" {
		before := len(incidents)
		incidents = filterOSPackages(incidents, filepath.Join(dataDir(), "state"))
		log.Printf("[sync][%s] OS package filter: %d -> %d (high/critical, fix or KEV)", modName, before, len(incidents))
	}
	return incidents
}

// mergeAndPersistModule loads prior on-disk state, merges with new incidents,
// assigns canonical IDs, attributes actors, and writes the authoritative haul data.
func (e *SyncEngine) mergeAndPersistModule(modName string, modCfg config.ModuleConfig, incidents []*incident.Incident, fetchErrCount int32) {
	// Load whatever is already on disk and fold it into the fetched set
	// before MergeAll. Without this, each cycle's persist call wipes any
	// incident that wasn't refreshed within the current `since` window —
	// supply collapsed from 264k → 0 and ransomware from 30k → 3 in a
	// single cron tick because most sources legitimately return nothing
	// new in 6 hours. MergeAll is union-find dedupe so re-feeding the
	// prior set is idempotent.
	priorCount := 0
	if priorIncidents, err := index.LoadAllJSONLShards(modCfg.OutputDir); err != nil {
		log.Printf("[sync][%s] load prior shards: %v (proceeding without prior state)", modName, err)
	} else if len(priorIncidents) > 0 {
		priorCount = len(priorIncidents)
		log.Printf("[sync][%s] loaded %d prior incidents from disk", modName, priorCount)
		incidents = append(priorIncidents, incidents...)
	}

	// MergeAll uses union-find bucketing by every package/campaign/IOC key,
	// so it's near-linear even on the 490k bulk-load case. We merge BEFORE
	// canonicalization so a source-prefixed record and its already-canonical
	// prior version dedup via shared CVE_ID / package keys, not by ID.
	log.Printf("[sync][%s] MergeAll: merging %d incidents", modName, len(incidents))
	mergeStart := time.Now()
	incidents = incident.MergeAll(incidents)
	assignCanonicalIDs(incidents, modName, e.sigmaReg)
	log.Printf("[sync][%s] MergeAll: done in %s (%d after merge)", modName, time.Since(mergeStart).Round(time.Second), len(incidents))

	// Actor attribution — O(incidents × actors), ~5s for 490k × 174.
	if e.actorStore != nil {
		attrStart := time.Now()
		incidents = actor.Attribute(incidents, e.actorStore, modName)
		log.Printf("[sync][%s] actor.Attribute: done in %s", modName, time.Since(attrStart).Round(time.Second))
	}

	// Persist the full merged incident set as the authoritative haul data.
	// Belt-and-braces shrink guard: refuse to persist if the post-merge set
	// lost more than half of what was on disk (bypass with --allow-shrink).
	if !syncDryRun {
		if priorCount > 1000 && len(incidents)*2 < priorCount && !syncAllowShrink {
			log.Printf("[sync][%s] REFUSING PERSIST: merged set (%d) is <50%% of prior on-disk (%d). "+
				"This usually means a source went silent or a since-window regressed. "+
				"Re-run with --allow-shrink if this is intentional.",
				modName, len(incidents), priorCount)
		} else {
			persistStart := time.Now()
			if err := index.WriteAllJSONLShards(incidents, modCfg.OutputDir); err != nil {
				log.Printf("[sync][%s] persist all.jsonl: %v", modName, err)
			}
			if err := index.WriteByPackageLookup(incidents, modCfg.OutputDir); err != nil {
				log.Printf("[sync][%s] persist by-package: %v", modName, err)
			}
			if err := index.WriteByCVELookup(modName, incidents, modCfg.OutputDir); err != nil {
				log.Printf("[sync][%s] persist by-cve: %v", modName, err)
			}
			if err := index.WriteCuratedIndex(modName, incidents, modCfg.OutputDir); err != nil {
				log.Printf("[sync][%s] persist index.json: %v", modName, err)
			}
			log.Printf("[sync][%s] persist: done in %s", modName, time.Since(persistStart).Round(time.Second))
		}
	}

	e.moduleIncidents[modName] = incidents
	e.moduleFetchErrors[modName] = fetchErrCount
}

// crossModuleDedup removes incidents shared across modules (keeping the
// highest-priority copy) and re-persists any module whose set changed.
//
// Priority: supply > malware > ransomware > cve > container — supply/malware/
// ransomware are most actionable; cve/container records are encyclopedic.
func (e *SyncEngine) crossModuleDedup() {
	if syncDryRun {
		return
	}
	dedupAcrossModules(e.moduleIncidents, []string{"supply", "malware", "ransomware", "cve", "container", "os-packages"})
	for _, modName := range e.moduleNames {
		modCfg, ok := e.cfg.Modules[modName]
		if !ok {
			continue
		}
		incidents := e.moduleIncidents[modName]
		if err := index.WriteAllJSONLShards(incidents, modCfg.OutputDir); err != nil {
			log.Printf("[sync][%s] dedup re-persist shards: %v", modName, err)
		}
		if err := index.WriteByPackageLookup(incidents, modCfg.OutputDir); err != nil {
			log.Printf("[sync][%s] dedup re-persist package lookup: %v", modName, err)
		}
		if err := index.WriteByCVELookup(modName, incidents, modCfg.OutputDir); err != nil {
			log.Printf("[sync][%s] dedup re-persist cve lookup: %v", modName, err)
		}
		if err := index.WriteCuratedIndex(modName, incidents, modCfg.OutputDir); err != nil {
			log.Printf("[sync][%s] dedup re-persist curated index: %v", modName, err)
		}
	}
}

// fetchBlogs fetches multi-domain blog sources and routes posts into per-module
// draft queues. Persists the multi-domain cursor on success.
func (e *SyncEngine) fetchBlogs(ctx context.Context) {
	if len(e.cfg.MultiDomainSources) == 0 {
		return
	}
	var mdSince time.Time
	if e.sinceOverride != nil {
		mdSince = *e.sinceOverride
	} else if src := e.st.Sources["__multidomain__"]; src.LastSync != nil {
		mdSince = *src.LastSync
	} else {
		mdSince = e.st.LastSync
	}

	for name, mdCfg := range e.cfg.MultiDomainSources {
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
				e.moduleDrafts[modName] = append(e.moduleDrafts[modName], inc)
				log.Printf("[sync][%s] routed %s post: %s", modName, name, post.Title)
			}
		}
	}

	if !syncDryRun && e.sinceOverride == nil {
		now := time.Now().UTC()
		if e.st.Sources == nil {
			e.st.Sources = make(map[string]state.SourceState)
		}
		src := e.st.Sources["__multidomain__"]
		src.LastSync = &now
		e.st.Sources["__multidomain__"] = src
		if err := e.stateMgr.Save(filepath.Join(dataDir(), "state/last_sync.json"), e.st); err != nil {
			log.Printf("[sync][multidomain] save state: %v", err)
		}
	}
}

// generateModule generates sigma rules and IOC feeds for one module's incidents,
// writes blog drafts, and persists the per-module cursor.
func (e *SyncEngine) generateModule(ctx context.Context, modName string, modCfg config.ModuleConfig) {
	_ = ctx // available for future use by generation backends
	incidents := e.moduleIncidents[modName]

	// v0.1.11 routing: per-incident sigma rules go under --rules-root when set, otherwise inline.
	sigmaOutDir := filepath.Join(moduleRulesDir(syncRulesRoot, modCfg.OutputDir), "sigma")
	feedsDir := filepath.Join(modCfg.OutputDir, "feeds")
	// Wipe stale Sigma files only on --backfill (full historical re-ingestion).
	// Incremental syncs must not wipe rules generated from earlier windows.
	if !syncDryRun && syncBackfill {
		_ = os.RemoveAll(sigmaOutDir)
	}
	gen := sigma.New(sigmaOutDir, modName, e.sigmaReg)

	genStart := time.Now()
	log.Printf("[sync][%s] generating rules + IOC feeds for %d incidents", modName, len(incidents))

	// Decide which incidents get sigma rules: same IsCurated predicate + cap
	// that governs STIX bundles and index.json. Apply cap only when rules
	// co-locate with intel in haul; uncapped under --rules-root (split mode).
	applyCap := syncRulesRoot == ""
	sigmaSet := buildSigmaEligibleSet(modName, incidents, applyCap)
	if applyCap {
		log.Printf("[sync][%s] sigma eligibility: %d of %d incidents qualify (curated, capped at %d)",
			modName, len(sigmaSet), len(incidents), index.CuratedCapFor(modName))
	} else {
		log.Printf("[sync][%s] sigma eligibility: %d of %d incidents qualify (curated, uncapped — split mode)",
			modName, len(sigmaSet), len(incidents))
	}

	// Parallel sigma + IOC generation — sigma.Registry is mutex-protected so
	// concurrent gen.Generate() calls are safe.
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers > len(incidents) {
		workers = len(incidents)
	}
	if workers < 1 {
		workers = 1
	}

	var (
		processed         atomic.Int64
		skippedTier4      atomic.Int64
		skippedNonCurated atomic.Int64
		genWG             sync.WaitGroup
		incidentsChan     = make(chan *incident.Incident, workers*2)
	)

	progressDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		lastReported := int64(0)
		for {
			select {
			case <-progressDone:
				return
			case <-ticker.C:
				n := processed.Load()
				if n-lastReported >= 20_000 || (n > 0 && lastReported == 0) {
					log.Printf("[sync][%s] generate progress: %d/%d (%s elapsed)",
						modName, n, len(incidents), time.Since(genStart).Round(time.Second))
					lastReported = n
				}
			}
		}
	}()

	for w := 0; w < workers; w++ {
		genWG.Add(1)
		go func() {
			defer genWG.Done()
			for inc := range incidentsChan {
				processed.Add(1)
				if syncDryRun {
					log.Printf("[sync][%s] dry-run: would generate rules for %s", modName, inc.ID)
					continue
				}
				// Tier-4 container records have no actionable indicators — skip sigma+IOC.
				if inc.ContainerExt != nil && inc.ContainerExt.Tier == 4 {
					skippedTier4.Add(1)
					continue
				}
				if sigmaSet[inc.ID] {
					if err := gen.Generate(inc); err != nil {
						log.Printf("[sync][%s] generate %s: %v", modName, inc.ID, err)
					}
				} else {
					skippedNonCurated.Add(1)
				}
				if inc.ContainerExt != nil {
					if err := e.iocExp.ExportContainerImages(inc, feedsDir); err != nil {
						log.Printf("[sync][%s] container export %s: %v", modName, inc.ID, err)
					}
				} else {
					if err := e.iocExp.Export(inc, feedsDir); err != nil {
						log.Printf("[sync][%s] ioc export %s: %v", modName, inc.ID, err)
					}
				}
			}
		}()
	}
	for _, inc := range incidents {
		incidentsChan <- inc
	}
	close(incidentsChan)
	genWG.Wait()
	close(progressDone)

	if t4 := skippedTier4.Load(); t4 > 0 {
		log.Printf("[sync][%s] skipped sigma+IOC for %d Tier-4 informational records", modName, t4)
	}
	if nc := skippedNonCurated.Load(); nc > 0 {
		log.Printf("[sync][%s] skipped sigma (kept IOC) for %d non-curated records", modName, nc)
	}
	log.Printf("[sync][%s] generate: done in %s", modName, time.Since(genStart).Round(time.Second))

	// Write multi-domain blog posts as draft YAMLs for human triage. Only
	// write drafts that carry at least one technical signal.
	if drafts := e.moduleDrafts[modName]; len(drafts) > 0 {
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

	// Persist per-module cursor. Skip when any source errored — re-fetching
	// from the old cursor on the next run is safer than skipping the window.
	if !syncDryRun && e.sinceOverride == nil && e.moduleFetchErrors[modName] == 0 {
		now := time.Now().UTC()
		if e.st.Sources == nil {
			e.st.Sources = make(map[string]state.SourceState)
		}
		src := e.st.Sources[modName]
		src.LastSync = &now
		e.st.Sources[modName] = src
		if err := e.stateMgr.Save(filepath.Join(dataDir(), "state/last_sync.json"), e.st); err != nil {
			log.Printf("[sync][%s] save state: %v", modName, err)
		}
	}
}

// persistState saves the sigma registry, actor profiles, and final state file.
func (e *SyncEngine) persistState() error {
	if !syncDryRun {
		if err := e.sigmaReg.Save(); err != nil {
			log.Printf("[sync] sigma registry save: %v", err)
		}
	}

	if syncDryRun {
		log.Printf("[sync] dry-run complete — no state updated")
		return nil
	}

	if e.actorStore != nil {
		if err := e.actorStore.WriteProfiles(filepath.Join(dataDir(), "actors/profiles")); err != nil {
			log.Printf("[sync] write actor profiles: %v", err)
		} else {
			withIncidents := 0
			for _, p := range e.actorStore.Profiles() {
				if len(p.LinkedIncidents) > 0 {
					withIncidents++
				}
			}
			log.Printf("[sync] actor profiles: %d total, %d with linked incidents",
				len(e.actorStore.Profiles()), withIncidents)
		}
	}

	// Note: we don't touch st.LastSync here. It exists for backwards
	// compatibility with state files written by older versions, but new
	// state writes only update the per-module cursor in st.Sources.
	// Cross-module fallback caused supply → malware silent-zero on first runs.
	return e.stateMgr.Save(filepath.Join(dataDir(), "state/last_sync.json"), e.st)
}

func runSync(_ *cobra.Command, _ []string) error {
	eng := newSyncEngine()
	if err := eng.loadConfig(); err != nil {
		return err
	}
	eng.loadPopularData()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Watchdog: hard os.Exit if the entire sync hasn't completed within
	// hardWallClockBudget. Absolute escape hatch when per-source ctx and
	// allSourcesDeadline both somehow fail to bail out.
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

	if err := eng.initRegistries(ctx); err != nil {
		return err
	}

	for _, modName := range eng.moduleNames {
		modCfg, ok := eng.cfg.Modules[modName]
		if !ok {
			if eng.explicitModule {
				return fmt.Errorf("unknown module %q", modName)
			}
			log.Printf("[sync] skipping module %q (not configured in dragnet.yaml)", modName)
			continue
		}
		since := eng.sinceFor(modName)
		incs, fetchErrCount, err := eng.fetchModule(ctx, modName, modCfg, since)
		if err != nil {
			return err
		}
		incs = eng.enrichModule(ctx, modName, since, modCfg, incs)
		eng.mergeAndPersistModule(modName, modCfg, incs, fetchErrCount)
	}

	eng.crossModuleDedup()
	eng.fetchBlogs(ctx)

	for _, modName := range eng.moduleNames {
		modCfg, ok := eng.cfg.Modules[modName]
		if !ok {
			continue
		}
		eng.generateModule(ctx, modName, modCfg)
	}

	return eng.persistState()
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
				actor.MergeLinkedIncidents(profiles, store)
				return actor.Load(profiles), newETag
			}
		}
		return store, newETag
	}
	log.Printf("[sync] mitre: loaded %d actor profiles from ATT&CK bundle", len(profiles))
	diskStore, _ := actor.ReadProfiles(filepath.Join(dataDir(), "actors/profiles"))
	actor.MergeLinkedIncidents(profiles, diskStore)
	return actor.Load(profiles), newETag
}

// writeDraftIncidents marshals draft incidents to YAML files at
// {draftsDir}/{year}/{id}.yaml. Year-tier sub-directories keep the per-year
// listing bounded (drafts accumulate unboundedly over time as blog feeds
// pump out post-incident write-ups) and let consumers `git sparse-checkout`
// a single year if they want.
func writeDraftIncidents(draftsDir string, drafts []*incident.Incident, dryRun bool, modName string) error {
	if dryRun {
		for _, d := range drafts {
			log.Printf("[sync][%s] dry-run: would write draft %s", modName, d.ID)
		}
		return nil
	}
	for _, d := range drafts {
		year := draftYear(d)
		yearDir := filepath.Join(draftsDir, year)
		if err := os.MkdirAll(yearDir, 0o755); err != nil {
			log.Printf("[sync][%s] mkdir %s: %v", modName, yearDir, err)
			continue
		}
		path := filepath.Join(yearDir, d.ID+".yaml")
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

// draftYear returns the four-digit year derived from the draft incident's
// compromise window start, or "unknown" if the field is empty / malformed.
func draftYear(d *incident.Incident) string {
	if d.CompromiseWindow.Start == "" {
		return "unknown"
	}
	if t, err := time.Parse(time.RFC3339, d.CompromiseWindow.Start); err == nil {
		return t.UTC().Format("2006")
	}
	return "unknown"
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

	// Build one Detector per ecosystem so normaliseHomoglyphs runs once per
	// popular package at construction time rather than on every comparison.
	detectors := make(map[string]*typosquat.Detector, len(popularByEco))
	for eco, pkgs := range popularByEco {
		if len(pkgs) > 0 {
			detectors[eco] = typosquat.NewDetector(pkgs, typosquatThreshold)
		}
	}

	_ = ctx // formerly used by FetchDownloads; kept on signature for compatibility

	for _, inc := range incidents {
		for _, pkg := range inc.Packages {
			det, ok := detectors[pkg.Ecosystem]
			if !ok {
				continue
			}

			// Typosquat detection.
			if match := det.Detect(pkg.Name); match != nil {
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
	popularIdx container.PopularIndex,
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
			// Drop: CISA/AttackerKB are wired into the container module's
			// source list as enrichers (to flag a Trivy CVE as KEV-listed or
			// PoC-available). MergeAll already unions by CVE_ID before this
			// point, so any CISA record that matches a Trivy entry has been
			// folded into that Trivy record (which carries ContainerExt).
			// The leftovers are CVEs CISA tracks that have no container
			// linkage at all (Windows desktop CVEs, kernel bugs in non-
			// container contexts, etc.) — they don't belong in the container
			// module's index.
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
			popularIdx,
			cfg,
		)
		if tier == 0 {
			// No popular-image linkage AND no KEV/PoC signal. Pre-v0.1.10 we
			// kept these as informational Tier-4 when no popular-images
			// snapshot was configured, which let the entire ~165k Trivy DB
			// land in container/incidents/all/. That bloats every consumer
			// (port listings, STIX bundle, sigma generation, manifest) for
			// records nobody would ever build detection from. v0.1.10 drops
			// them unconditionally; if container's output looks empty, run
			// `dragnet update-popular --module container` to seed the
			// popular-images snapshot so Tier 1/2/3 can fire.
			continue
		}
		inc.ContainerExt.Tier = tier
		out = append(out, inc)
	}
	return out
}

// assignCanonicalIDs rewrites each incident's ID to its canonical
// dragnet-{module}-{year}-{seq} form via the sigma registry, preserving the
// original source-prefixed ID in LegacyID. Called at ingest time so every
// downstream artifact (shards, lookup, index, feeds, STIX, sigma rules)
// references the same identifier. Idempotent: an incident that already has
// a canonical ID (because it was loaded back from disk) passes through
// unchanged.
//
// firstSeen drives the year bucket — compromise_window.start when available,
// time.Now() otherwise. The registry's same-input-same-output guarantee
// means re-running this against the same data produces the same IDs.
func assignCanonicalIDs(incidents []*incident.Incident, module string, reg *sigma.Registry) {
	for _, inc := range incidents {
		if inc == nil || inc.ID == "" {
			continue
		}
		if strings.HasPrefix(inc.ID, "dragnet-") {
			continue // already canonical
		}
		firstSeen := time.Time{}
		if inc.CompromiseWindow.Start != "" {
			if t, err := time.Parse(time.RFC3339, inc.CompromiseWindow.Start); err == nil {
				firstSeen = t
			}
		}
		canonical := reg.AssignID(module, inc.ID, firstSeen)
		// Only set LegacyID if the rewrite actually changed the ID — guards
		// against the (impossible-here but defensive) case where canonical
		// happens to equal the input.
		if canonical != inc.ID {
			inc.LegacyID = inc.ID
			inc.ID = canonical
		}
	}
}

// dedupAcrossModules removes any incident that appears in more than one
// module's slice, keeping it only in the highest-priority module per `order`.
// Mutates the map in place. Logs the per-module drop counts so workflow
// output captures the size of the dedup churn.
//
// Dedup key prefers LegacyID over ID because ingest-time canonicalization
// assigns module-specific canonical IDs (the same source CISA record gets
// dragnet-cve-2026-0001 in the cve module and dragnet-container-2026-0001
// in the container module — different IDs, same source record). The
// LegacyID is the stable source-prefixed identifier that's the same across
// modules. Falls back to ID for incidents that were already canonical
// before v0.1.10 (no LegacyID set).
func dedupAcrossModules(moduleIncidents map[string][]*incident.Incident, order []string) {
	claimed := map[string]string{} // dedupKey -> owning module
	dropped := map[string]int{}    // module -> count

	for _, mod := range order {
		incidents, ok := moduleIncidents[mod]
		if !ok {
			continue
		}
		kept := incidents[:0]
		for _, inc := range incidents {
			if inc == nil {
				kept = append(kept, inc)
				continue
			}
			key := inc.LegacyID
			if key == "" {
				key = inc.ID
			}
			if key == "" {
				kept = append(kept, inc)
				continue
			}
			if owner, seen := claimed[key]; seen {
				dropped[mod]++
				_ = owner
				continue
			}
			claimed[key] = mod
			kept = append(kept, inc)
		}
		moduleIncidents[mod] = kept
	}

	for mod, n := range dropped {
		if n > 0 {
			log.Printf("[sync][cross-dedup] dropped %d duplicate(s) from %s (claimed by an earlier module)", n, mod)
		}
	}
}

// filterCVEByQuality narrows the cve module's set to records likely to inform
// detection work, dropping the long tail of disclosed-but-never-exploited CVEs
// that bloat consumers without informing rules. Kept:
//   - KEV-listed (CVEExt.ExploitedInWild) — CISA's actively-exploited catalog
//   - CVSS >= 9 — critical scoring even without observed exploitation
//   - public PoC available (CVEExt.ExploitPublic) — proof-of-concept makes the
//     CVE materially more dangerous
//   - actor-linked (ActorIDs not empty) — TTPs we track
//
// Records without CVEExt at all pass through unchanged so non-NVD sources
// (e.g. blogs writing about a CVE) aren't accidentally filtered out.
func filterCVEByQuality(incidents []*incident.Incident) []*incident.Incident {
	out := make([]*incident.Incident, 0, len(incidents))
	for _, inc := range incidents {
		if inc.CVEExt == nil {
			out = append(out, inc)
			continue
		}
		if inc.CVEExt.ExploitedInWild ||
			inc.CVEExt.ExploitPublic ||
			inc.CVEExt.CVSSScore >= 9.0 ||
			len(inc.ActorIDs) > 0 {
			out = append(out, inc)
		}
	}
	return out
}

// fileExists reports whether a file exists at path.
// buildSigmaEligibleSet returns the set of incident IDs that should produce
// sigma rules. Filter: IsCuratedFor (severe / actor-linked / recent, with
// supply keeping medium severity).
//
// When applyCap is true (v0.1.10 behaviour, rules co-located with intel in
// haul), the set is sorted by published-date desc and capped at the module's
// configured curated cap so haul's git size stays manageable.
//
// When applyCap is false (v0.1.11+ with --rules-root pointing at haul-rules),
// rules live in a separate repo and don't compete for space — generate for
// every curated incident, no cap.
func buildSigmaEligibleSet(module string, incidents []*incident.Incident, applyCap bool) map[string]bool {
	cutoff := time.Now().UTC().Add(-index.CuratedRecentWindow)
	curated := make([]*incident.Incident, 0, len(incidents))
	for _, inc := range incidents {
		if index.IsCuratedFor(module, inc, cutoff) {
			curated = append(curated, inc)
		}
	}
	if applyCap {
		sort.Slice(curated, func(i, j int) bool {
			return index.PublishedAt(curated[i]).After(index.PublishedAt(curated[j]))
		})
		if cap := index.CuratedCapFor(module); cap > 0 && len(curated) > cap {
			curated = curated[:cap]
		}
	}
	set := make(map[string]bool, len(curated))
	for _, inc := range curated {
		set[inc.ID] = true
	}
	return set
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// filterOSPackages narrows an os-packages incident set to high-signal advisories:
// severity high/critical, has a fix version or is KEV-listed. When
// state/image_packages.json exists it additionally restricts to packages present
// in popular container images; when the file is absent that gate is skipped.
func filterOSPackages(incidents []*incident.Incident, stateDir string) []*incident.Incident {
	// Load image packages if available; nil = gate disabled.
	imgPackageMap, err := state.LoadImagePackages(stateDir)
	if err != nil {
		log.Printf("[sync][os-packages] load image_packages.json: %v (skipping image-presence gate)", err)
	}
	var imgPkgSet map[string]bool
	if len(imgPackageMap) > 0 {
		imgPkgSet = state.ImagePackagesAsSet(imgPackageMap)
		log.Printf("[sync][os-packages] image-presence gate active: %d unique packages", len(imgPkgSet))
	}

	filter := osv.NewOSFilter(imgPkgSet, true)
	return filter.FilterAll(incidents)
}
