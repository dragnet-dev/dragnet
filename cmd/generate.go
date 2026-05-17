package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

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
	genModule      string
	genBackends    string
	genLayers      string
	genCSIOCAction string
)

func init() {
	generateCmd.Flags().StringVar(&genModule, "module", "all",
		"Module to generate for: supply|malware|ransomware|cve|all")
	generateCmd.Flags().StringVar(&genBackends, "backends", "all",
		"Comma-separated backends to compile, or 'all'")
	generateCmd.Flags().StringVar(&genLayers, "layers", "all",
		"Comma-separated layers: exposure,ioc,hunting, or 'all'")
	generateCmd.Flags().StringVar(&genCSIOCAction, "cs-ioc-action", "detect",
		"CrowdStrike IOC action: detect or prevent")
}

func runGenerate(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}

	moduleNames := resolveModules(genModule)

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

	validLayers := map[string]bool{"exposure": true, "ioc": true, "hunting": true}
	layers := map[string]bool{}
	if genLayers == "all" {
		layers["exposure"] = true
		layers["ioc"] = true
		layers["hunting"] = true
	} else {
		for _, l := range strings.Split(genLayers, ",") {
			if !validLayers[l] {
				return fmt.Errorf("unknown layer %q (valid: exposure, ioc, hunting)", l)
			}
			layers[l] = true
		}
	}

	wantSTIX := genBackends == "all" || slices.Contains(strings.Split(genBackends, ","), "stix")

	allModuleIncidents := map[string][]*incident.Incident{}

	for _, modName := range moduleNames {
		modCfg, ok := cfg.Modules[modName]
		if !ok {
			return fmt.Errorf("unknown module %q", modName)
		}

		sigmaRoot := filepath.Join(modCfg.OutputDir, "rules", "sigma")
		var sigmaFiles []string
		for layer := range layers {
			dir := filepath.Join(sigmaRoot, layer)
			entries, err := os.ReadDir(dir)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return err
			}
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
					sigmaFiles = append(sigmaFiles, filepath.Join(dir, e.Name()))
				}
			}
		}

		for _, sf := range sigmaFiles {
			data, err := os.ReadFile(sf)
			if err != nil {
				log.Printf("[generate][%s] read %s: %v", modName, sf, err)
				continue
			}
			for _, b := range be {
				out, err := b.Compile(data)
				if err != nil {
					log.Printf("[generate][%s] %s compile %s: %v", modName, b.Name(), sf, err)
					continue
				}
				dest := moduleRuleOutputPath(b, sf, sigmaRoot, modCfg.OutputDir)
				if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(dest, out, 0o644); err != nil {
					log.Printf("[generate][%s] write %s: %v", modName, dest, err)
				}
			}
		}

		// Load module incidents from JSONL shards once, unconditionally —
		// search index and STIX both consume them. Loading is fast (~5 s
		// per module); the expensive work is the per-incident STIX
		// validation downstream, which we gate separately.
		incidentsDir := filepath.Join(modCfg.OutputDir, "incidents")
		modIncidents, err := loadModuleIncidentsFromShards(modName, incidentsDir)
		if err != nil {
			log.Printf("[generate][%s] load incidents: %v", modName, err)
		}
		allModuleIncidents[modName] = modIncidents

		if wantSTIX {
			stixOutDir := filepath.Join(modCfg.OutputDir, "feeds", "stix")
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
// pre-loaded incidents. Tier-4 container records (informational, the bulk
// Trivy DB) are skipped — they have no actionable indicators and including
// 158k of them in STIX validation adds ~15 min to the run for zero downstream
// value.
func writeModuleSTIX(modName string, incidents []*incident.Incident, stixOutDir string) error {
	var bundles []stix.Bundle
	skipped := 0
	for _, inc := range incidents {
		if inc.ContainerExt != nil && inc.ContainerExt.Tier == 4 {
			skipped++
			continue
		}
		bundle := stix.GenerateBundle(inc)
		if errs := stix.Validate(bundle); len(errs) > 0 {
			// Validation errors are logged once per bundle but not per-error
			// to avoid log floods on the bulk OSV records that legitimately
			// don't have STIX-shaped indicators.
			continue
		}
		bundles = append(bundles, bundle)
	}
	if skipped > 0 {
		log.Printf("[generate][%s] stix: skipped %d Tier-4 informational records", modName, skipped)
	}
	log.Printf("[generate][%s] stix: %d valid bundles of %d incidents", modName, len(bundles), len(incidents))

	if len(bundles) == 0 {
		return nil
	}

	combined := stix.BuildCombinedBundle(bundles)
	if errs := stix.Validate(combined); len(errs) > 0 {
		for _, e := range errs {
			log.Printf("[generate][%s] stix bundle: %s", modName, e)
		}
		return fmt.Errorf("combined stix bundle for %s has %d validation error(s) — not written", modName, len(errs))
	}
	data, err := json.MarshalIndent(combined, "", "  ")
	if err != nil {
		return err
	}
	dest := filepath.Join(stixOutDir, "bundle.json")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
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

func generateRootSTIX(allModules map[string][]*incident.Incident) error {
	var bundles []stix.Bundle
	for _, incidents := range allModules {
		for _, inc := range incidents {
			bundles = append(bundles, stix.GenerateBundle(inc))
		}
	}
	if len(bundles) == 0 {
		return nil
	}
	combined := stix.BuildCombinedBundle(bundles)
	if errs := stix.Validate(combined); len(errs) > 0 {
		return fmt.Errorf("root stix bundle has %d validation error(s) — not written", len(errs))
	}
	data, err := json.MarshalIndent(combined, "", "  ")
	if err != nil {
		return err
	}
	dest := filepath.Join("feeds", "stix", "bundle.json")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
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
