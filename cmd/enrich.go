package cmd

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/config"
	"github.com/dragnet-dev/dragnet/internal/enrichment"
	onlineenrich "github.com/dragnet-dev/dragnet/internal/enrichment/online"
	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/dragnet-dev/dragnet/internal/index"
	"github.com/dragnet-dev/dragnet/internal/state"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var enrichCmd = &cobra.Command{
	Use:   "enrich",
	Short: "Run cross-domain enrichment across all modules",
	RunE:  runEnrich,
}

var (
	enrichCrossDomain bool
	enrichOnline      bool
	enrichCacheFile   string
)

func init() {
	enrichCmd.Flags().BoolVar(&enrichCrossDomain, "cross-domain", false,
		"Apply cross-domain IOC confidence boosting and actor/infrastructure linking")
	enrichCmd.Flags().BoolVar(&enrichOnline, "online", false,
		"Enrich IP/domain IOCs via RIPEstat, Shodan InternetDB, and crt.sh")
	enrichCmd.Flags().StringVar(&enrichCacheFile, "cache-file", "state/enrichment-cache.json",
		"Path to the online enrichment cache file")
}

func runEnrich(_ *cobra.Command, _ []string) error {
	if !enrichCrossDomain && !enrichOnline {
		log.Println("[enrich] nothing to do — pass --cross-domain and/or --online")
		return nil
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}

	allModules := map[string][]*incident.Incident{}
	moduleOutDir := map[string]string{}

	for _, modName := range config.ModuleNames {
		modCfg, ok := cfg.Modules[modName]
		if !ok {
			continue
		}
		incidents, err := loadModuleIncidents(modCfg.OutputDir)
		if err != nil {
			log.Printf("[enrich] load %s: %v", modName, err)
			continue
		}
		allModules[modName] = incidents
		moduleOutDir[modName] = modCfg.OutputDir
		log.Printf("[enrich] loaded %d incidents from %s", len(incidents), modName)
	}

	if enrichCrossDomain {
		enr := enrichment.New(cfg.CrossEnrichment)
		enr.Enrich(allModules)
	}

	if enrichOnline {
		cache, err := state.LoadEnrichmentCache(enrichCacheFile)
		if err != nil {
			log.Printf("[enrich] load cache %s: %v (starting fresh)", enrichCacheFile, err)
			cache = state.NewEnrichmentCache()
		}
		saveFn := func() {
			if err := state.SaveEnrichmentCache(enrichCacheFile, cache); err != nil {
				log.Printf("[enrich] periodic cache save: %v", err)
			} else {
				log.Printf("[enrich] periodic cache save: ok")
			}
		}
		enr := onlineenrich.New(cfg.OnlineEnrichment, cache)
		n := enr.EnrichAllWithSave(context.Background(), allModules, saveFn)
		log.Printf("[enrich] online: %d new enrichments", n)
		if err := state.SaveEnrichmentCache(enrichCacheFile, cache); err != nil {
			log.Printf("[enrich] save cache: %v", err)
		}
	}

	// Persist enriched results. The bulk dataset lives in all/*.jsonl
	// (re-written here so cross_domain_links / ip_enrichment / domain_enrichment
	// are visible to downstream consumers); per-incident YAMLs rewritten only
	// when cross-domain links are present (online metadata only lives in JSONL).
	for modName, incidents := range allModules {
		outDir := moduleOutDir[modName]

		needsPersist := false
		for _, inc := range incidents {
			if len(inc.CrossDomainLinks) > 0 || len(inc.CrossDomainSources) > 0 {
				needsPersist = true
				break
			}
			if enrichOnline {
				for _, ip := range inc.Indicators.IPs {
					if ip.IPEnrich != nil {
						needsPersist = true
						break
					}
				}
				if needsPersist {
					break
				}
				for _, d := range inc.Indicators.Domains {
					if d.DomainEnrich != nil {
						needsPersist = true
						break
					}
				}
			}
			if needsPersist {
				break
			}
		}
		if !needsPersist {
			continue
		}

		log.Printf("[enrich] persisting %s shards", modName)
		if err := index.WriteAllJSONLShards(incidents, outDir); err != nil {
			log.Printf("[enrich] persist %s shards: %v", modName, err)
		}

		if !enrichCrossDomain {
			continue
		}
		// Rewrite per-incident YAMLs only for cross-domain links (online
		// enrichment metadata is JSONL-only to avoid YAML churn).
		incidentsDir := filepath.Join(outDir, "incidents")
		for _, inc := range incidents {
			if len(inc.CrossDomainLinks) == 0 && len(inc.CrossDomainSources) == 0 {
				continue
			}
			path := findIncidentFile(incidentsDir, inc.ID)
			if path == "" {
				continue // record only lives in JSONL shards — that's fine, already written
			}
			if err := writeIncidentYAML(path, inc); err != nil {
				log.Printf("[enrich] write %s: %v", path, err)
			}
		}
	}

	return nil
}

// loadModuleIncidents loads every incident known to the module — both per-
// incident YAML files (legacy / hand-curated drafts that got merged) and
// the all/*.jsonl shards (the canonical bulk dataset). Each path on its
// own is incomplete: YAML-only would miss the 165k bulk-loaded records,
// JSONL-only would miss handcurated drafts that haven't migrated.
func loadModuleIncidents(outDir string) ([]*incident.Incident, error) {
	var out []*incident.Incident
	seen := map[string]bool{}

	incidentsDir := filepath.Join(outDir, "incidents")
	_ = filepath.WalkDir(incidentsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		if strings.Contains(path, string(filepath.Separator)+"drafts"+string(filepath.Separator)) {
			return nil
		}
		inc, err := incident.Load(path)
		if err != nil {
			log.Printf("[enrich] load %s: %v (skipping)", path, err)
			return nil
		}
		if !seen[inc.ID] {
			seen[inc.ID] = true
			out = append(out, inc)
		}
		return nil
	})

	allDir := filepath.Join(incidentsDir, "all")
	entries, _ := os.ReadDir(allDir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		incs, err := loadIncidentsJSONL(filepath.Join(allDir, e.Name()))
		if err != nil {
			log.Printf("[enrich] load %s: %v (skipping)", e.Name(), err)
			continue
		}
		for _, inc := range incs {
			if !seen[inc.ID] {
				seen[inc.ID] = true
				out = append(out, inc)
			}
		}
	}
	return out, nil
}

func findIncidentFile(incidentsDir, id string) string {
	var found string
	_ = filepath.WalkDir(incidentsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.TrimSuffix(filepath.Base(path), ".yaml") == id {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func writeIncidentYAML(path string, inc *incident.Incident) error {
	data, err := yaml.Marshal(inc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
