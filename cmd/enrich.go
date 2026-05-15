package cmd

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/config"
	"github.com/dragnet-dev/dragnet/internal/enrichment"
	"github.com/dragnet-dev/dragnet/internal/incident"
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

	for _, modName := range config.ModuleNames {
		modCfg, ok := cfg.Modules[modName]
		if !ok {
			continue
		}
		incidentsDir := filepath.Join(modCfg.OutputDir, "incidents")
		incidents, err := loadAllIncidents(incidentsDir)
		if err != nil {
			log.Printf("[enrich] load %s: %v", modName, err)
			continue
		}
		allModules[modName] = incidents
		log.Printf("[enrich] loaded %d incidents from %s", len(incidents), modName)
	}

	enr := enrichment.New(cfg.CrossEnrichment)
	enr.Enrich(allModules)

	// Write enriched incidents back in-place
	for modName, incidents := range allModules {
		modCfg := cfg.Modules[modName]
		incidentsDir := filepath.Join(modCfg.OutputDir, "incidents")
		for _, inc := range incidents {
			if len(inc.CrossDomainLinks) == 0 && len(inc.CrossDomainSources) == 0 {
				continue
			}
			// Find the file and rewrite it
			path := findIncidentFile(incidentsDir, inc.ID)
			if path == "" {
				log.Printf("[enrich] could not locate file for %s", inc.ID)
				continue
			}
			if err := writeIncidentYAML(path, inc); err != nil {
				log.Printf("[enrich] write %s: %v", path, err)
			} else {
				log.Printf("[enrich] updated %s (%d cross-domain links)", inc.ID, len(inc.CrossDomainLinks))
			}
		}
	}

	return nil
}

func loadAllIncidents(incidentsDir string) ([]*incident.Incident, error) {
	var out []*incident.Incident
	err := filepath.WalkDir(incidentsDir, func(path string, d os.DirEntry, err error) error {
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
		out = append(out, inc)
		return nil
	})
	return out, err
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
