package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/config"
	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate incident YAML files against the schema",
	RunE:  runValidate,
}

var (
	validateModule        string
	validateIncludeDrafts bool
)

func init() {
	validateCmd.Flags().StringVar(&validateModule, "module", "all",
		"Module to validate: supply|malware|ransomware|cve|all")
	validateCmd.Flags().BoolVar(&validateIncludeDrafts, "include-drafts", false,
		"Also validate {module}/incidents/drafts/")
}

func runValidate(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}

	moduleNames := resolveModules(validateModule)

	var failures []string
	for _, modName := range moduleNames {
		modCfg, ok := cfg.Modules[modName]
		if !ok {
			return fmt.Errorf("unknown module %q", modName)
		}

		incidentsDir := filepath.Join(modCfg.OutputDir, "incidents")
		var dirs []string

		entries, err := os.ReadDir(incidentsDir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		// Top-level YAML files in the incidents dir itself
		dirs = append(dirs, incidentsDir)
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if e.Name() == "drafts" {
				if validateIncludeDrafts {
					dirs = append(dirs, filepath.Join(incidentsDir, "drafts"))
				}
				continue
			}
			dirs = append(dirs, filepath.Join(incidentsDir, e.Name()))
		}

		draftsDir := filepath.Join(incidentsDir, "drafts")
		for _, dir := range dirs {
			dirEntries, err := os.ReadDir(dir)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return err
			}
			isDrafts := dir == draftsDir
			for _, e := range dirEntries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
					continue
				}
				path := filepath.Join(dir, e.Name())
				var loadErr error
				if isDrafts {
					_, loadErr = incident.LoadDraft(path)
				} else {
					_, loadErr = incident.Load(path)
				}
				if loadErr != nil {
					log.Printf("[validate][%s] FAIL %s: %v", modName, path, loadErr)
					failures = append(failures, path)
				} else {
					log.Printf("[validate][%s] OK   %s", modName, path)
				}
			}
		}
	}

	if len(failures) > 0 {
		return fmt.Errorf("%d incident(s) failed validation", len(failures))
	}
	return nil
}
