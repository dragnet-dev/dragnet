package cmd

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/config"
	"github.com/dragnet-dev/dragnet/internal/enrichment"
	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/dragnet-dev/dragnet/internal/index"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var enrichCmd = &cobra.Command{
	Use:   "enrich",
	Short: "Run cross-domain enrichment across all modules",
	RunE:  runEnrich,
}

var enrichCrossDomain bool

func init() {
	enrichCmd.Flags().BoolVar(&enrichCrossDomain, "cross-domain", false,
		"Apply cross-domain IOC confidence boosting and actor/infrastructure linking")
}

func runEnrich(_ *cobra.Command, _ []string) error {
	if !enrichCrossDomain {
		log.Println("[enrich] nothing to do — pass --cross-domain")
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

	enr := enrichment.New(cfg.CrossEnrichment)
	enr.Enrich(allModules)

	// Persist enriched results. The bulk dataset lives in all/*.jsonl
	// (re-written here so cross_domain_links are visible to downstream
	// consumers); the per-incident YAMLs we still rewrite in case anyone
	// has hand-curated drafts that need the link annotations too.
	for modName, incidents := range allModules {
		outDir := moduleOutDir[modName]
		linked := 0
		for _, inc := range incidents {
			if len(inc.CrossDomainLinks) > 0 || len(inc.CrossDomainSources) > 0 {
				linked++
			}
		}
		if linked == 0 {
			continue
		}
		log.Printf("[enrich] %s: %d incidents gained cross-domain links", modName, linked)

		if err := index.WriteAllJSONLShards(incidents, outDir); err != nil {
			log.Printf("[enrich] persist %s shards: %v", modName, err)
		}

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
