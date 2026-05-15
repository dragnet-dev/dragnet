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

		if wantSTIX {
			incidentsDir := filepath.Join(modCfg.OutputDir, "incidents")
			stixOutDir := filepath.Join(modCfg.OutputDir, "feeds", "stix")
			modIncidents, err := generateModuleSTIX(modName, incidentsDir, stixOutDir)
			if err != nil {
				log.Printf("[generate][%s] stix: %v", modName, err)
			}
			allModuleIncidents[modName] = modIncidents

			if err := index.GenerateModuleIndex(modName, modIncidents, modCfg.OutputDir); err != nil {
				log.Printf("[generate][%s] index: %v", modName, err)
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

	// Root combined outputs when all modules are processed with STIX
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

func generateModuleSTIX(modName, incidentsDir, stixOutDir string) ([]*incident.Incident, error) {
	var bundles []stix.Bundle
	var incidents []*incident.Incident

	err := filepath.WalkDir(incidentsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		if strings.Contains(path, string(filepath.Separator)+"drafts"+string(filepath.Separator)) {
			return nil
		}

		inc, err := incident.Load(path)
		if err != nil {
			log.Printf("[generate][%s] stix load %s: %v", modName, path, err)
			return nil
		}
		incidents = append(incidents, inc)

		bundle := stix.GenerateBundle(inc)
		if errs := stix.Validate(bundle); len(errs) > 0 {
			for _, e := range errs {
				log.Printf("[generate][%s] stix %s: %s", modName, inc.ID, e)
			}
			return nil
		}
		bundles = append(bundles, bundle)

		data, err := json.MarshalIndent(bundle, "", "  ")
		if err != nil {
			return err
		}
		dest := filepath.Join(stixOutDir, inc.ID+".json")
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dest, data, 0o644)
	})
	if err != nil {
		return incidents, err
	}

	if len(bundles) == 0 {
		return incidents, nil
	}

	combined := stix.BuildCombinedBundle(bundles)
	if errs := stix.Validate(combined); len(errs) > 0 {
		for _, e := range errs {
			log.Printf("[generate][%s] stix bundle: %s", modName, e)
		}
		return incidents, fmt.Errorf("combined stix bundle for %s has %d validation error(s) — not written", modName, len(errs))
	}
	data, err := json.MarshalIndent(combined, "", "  ")
	if err != nil {
		return incidents, err
	}
	dest := filepath.Join(stixOutDir, "bundle.json")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return incidents, err
	}
	return incidents, os.WriteFile(dest, data, 0o644)
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
