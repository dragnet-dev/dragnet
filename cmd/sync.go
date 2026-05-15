package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/dragnet-dev/dragnet/internal/actor"
	"github.com/dragnet-dev/dragnet/internal/config"
	"github.com/dragnet-dev/dragnet/internal/container"
	"github.com/dragnet-dev/dragnet/internal/incident"
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
		// Priority: explicit --since > per-module cursor > global LastSync.
		var since time.Time
		if sinceOverride != nil {
			since = *sinceOverride
		} else if src := st.Sources[modName]; src.LastSync != nil {
			since = *src.LastSync
		} else {
			since = st.LastSync
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
		)
		sem := make(chan struct{}, 10)
		for _, src := range srcs {
			wg.Add(1)
			go func(s sources.Source) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				log.Printf("[sync][%s] fetching %s since %s", modName, s.Name(), since.Format(time.RFC3339))
				fetchCtx, fetchCancel := context.WithTimeout(ctx, 2*time.Minute)
				got, err := s.Fetch(fetchCtx, since)
				fetchCancel()
				if err != nil {
					log.Printf("[sync][%s] %s: %v (skipping)", modName, s.Name(), err)
					atomic.AddInt32(&fetchErrCount, 1)
					return
				}
				mu.Lock()
				incidents = append(incidents, got...)
				mu.Unlock()
			}(src)
		}
		wg.Wait()

		// OSV package enrichment for the supply module.
		if modName == "supply" {
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
				osvClient := osv.New()
				enriched, err := osvClient.EnrichPackages(ctx, pkgsToEnrich)
				if err != nil {
					log.Printf("[sync][%s] osv enrich: %v (skipping)", modName, err)
				} else if len(enriched) > 0 {
					log.Printf("[sync][%s] osv enrich: %d additional advisories", modName, len(enriched))
					incidents = append(incidents, enriched...)
				}
			}

			// Typosquat detection + impact scoring for supply module.
			incidents = enrichSupplyIncidents(ctx, incidents, popularByEco)
		}

		if modName == "container" {
			incidents = enrichContainerIncidents(incidents, popularImages, cfg.Modules["container"])
		}

		incidents = incident.MergeAll(incidents)

		// Actor attribution — links incidents to ATT&CK actor profiles.
		if actorStore != nil {
			incidents = actor.Attribute(incidents, actorStore, modName)
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

		for _, inc := range incidents {
			if syncDryRun {
				log.Printf("[sync][%s] dry-run: would generate rules for %s", modName, inc.ID)
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

	// Update global LastSync as a fallback for new modules added in future.
	st.LastSync = time.Now().UTC()
	return stateMgr.Save(filepath.Join(dataDir(), "state/last_sync.json"), st)
}

// loadActorStore fetches the MITRE ATT&CK bundle (ETag-cached) and returns an
// actor store. Falls back to on-disk profiles when the bundle is unchanged.
// Returns (store, newETag) — newETag is empty when no download occurred.
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
func enrichSupplyIncidents(ctx context.Context, incidents []*incident.Incident, popularByEco map[string][]popularity.PopularPackage) []*incident.Incident {
	const typosquatThreshold = 0.80

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

		// Impact scoring — fetch download stats for all affected packages concurrently.
		var (
			impMu          sync.Mutex
			packageImpacts []incident.PackageImpact
			totalWeekly    int64
		)
		var wg sync.WaitGroup
		for _, pkg := range inc.Packages {
			wg.Add(1)
			go func(p incident.Package) {
				defer wg.Done()
				stats, err := popularity.FetchDownloads(ctx, p.Ecosystem, p.Name)
				if err != nil || stats == nil {
					return
				}
				rating := string(popularity.ComputeImpactRating(stats.Weekly))
				imp := incident.PackageImpact{
					Name:             p.Name,
					Ecosystem:        p.Ecosystem,
					WeeklyDownloads:  stats.Weekly,
					MonthlyDownloads: stats.Monthly,
					ImpactRating:     rating,
					FetchedAt:        stats.FetchedAt,
				}
				impMu.Lock()
				packageImpacts = append(packageImpacts, imp)
				totalWeekly += stats.Weekly
				impMu.Unlock()
			}(pkg)
		}
		wg.Wait()

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
			continue // below threshold
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
