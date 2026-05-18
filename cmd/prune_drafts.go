// Package cmd: `dragnet prune-drafts` removes draft YAMLs that have aged out
// of triage — drafts that have been sitting in {module}/incidents/drafts/
// untouched for longer than the retention window. Default 30 days.
//
// Drafts come from the multi-domain blog-post router: vendor writeups get
// converted to draft YAMLs for human review before they enter the merged
// dataset. Most get merged or rejected within days. Anything that sits for
// a month is either irrelevant or forgotten; either way it's noise.
package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/config"
	"github.com/spf13/cobra"
)

var pruneDraftsCmd = &cobra.Command{
	Use:          "prune-drafts",
	Short:        "Delete draft YAMLs older than --max-age",
	SilenceUsage: true,
	RunE:         runPruneDrafts,
}

var (
	pruneRoot   string
	pruneMaxAge time.Duration
	pruneDryRun bool
)

func init() {
	pruneDraftsCmd.Flags().StringVar(&pruneRoot, "root", ".",
		"haul repo root (default cwd)")
	pruneDraftsCmd.Flags().DurationVar(&pruneMaxAge, "max-age", 30*24*time.Hour,
		"Maximum age for a draft before pruning (default 30d)")
	pruneDraftsCmd.Flags().BoolVar(&pruneDryRun, "dry-run", false,
		"Print what would be pruned without deleting")
}

func runPruneDrafts(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load(filepath.Join(pruneRoot, filepath.Base(cfgFile)))
	if err != nil {
		log.Printf("[prune-drafts] no dragnet.yaml at root (%v) — using default module list", err)
	}

	cutoff := time.Now().Add(-pruneMaxAge)
	total := 0
	for _, mod := range []string{"supply", "malware", "ransomware", "cve", "container"} {
		outputDir := mod
		if cfg != nil {
			if mc, ok := cfg.Modules[mod]; ok && mc.OutputDir != "" {
				outputDir = mc.OutputDir
			}
		}
		// Drafts can live either flat in drafts/ or year-bucketed in drafts/{year}/.
		draftsRoot := filepath.Join(pruneRoot, outputDir, "incidents", "drafts")
		pruned, kept, err := pruneDraftsIn(draftsRoot, cutoff, pruneDryRun)
		if err != nil {
			log.Printf("[prune-drafts][%s] %v", mod, err)
			continue
		}
		if pruned+kept > 0 {
			verb := "would prune"
			if !pruneDryRun {
				verb = "pruned"
			}
			log.Printf("[prune-drafts][%s] %s %d, kept %d (under %s)", mod, verb, pruned, kept, pruneMaxAge)
		}
		total += pruned
	}

	if pruneDryRun {
		log.Printf("[prune-drafts] DRY-RUN. Would prune %d draft(s) total. Re-run without --dry-run to apply.", total)
	} else {
		log.Printf("[prune-drafts] pruned %d draft(s) total", total)
	}
	return nil
}

// pruneDraftsIn walks dir (one level deep, plus immediate subdirs for the
// year-bucketed layout) and removes *.yaml files whose mtime is older than
// cutoff. Returns (pruned, kept, error).
func pruneDraftsIn(dir string, cutoff time.Time, dryRun bool) (int, int, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return 0, 0, nil
	}
	pruned, kept := 0, 0
	walk := func(path string) {
		fi, err := os.Stat(path)
		if err != nil {
			return
		}
		if fi.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return
		}
		if fi.ModTime().Before(cutoff) {
			if dryRun {
				log.Printf("[prune-drafts] would delete %s (mtime %s)", path, fi.ModTime().Format(time.RFC3339))
			} else if err := os.Remove(path); err != nil {
				log.Printf("[prune-drafts] delete %s: %v", path, err)
				return
			}
			pruned++
		} else {
			kept++
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, fmt.Errorf("read %s: %w", dir, err)
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if e.IsDir() {
			// Year-bucket layer
			sub, _ := os.ReadDir(path)
			for _, s := range sub {
				walk(filepath.Join(path, s.Name()))
			}
			continue
		}
		walk(path)
	}
	return pruned, kept, nil
}
