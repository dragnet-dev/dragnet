package cmd

import (
	"fmt"
	"log"

	"github.com/dragnet-dev/dragnet/internal/manifest"
	"github.com/spf13/cobra"
)

var manifestRoot string

var manifestCmd = &cobra.Command{
	Use:   "manifest",
	Short: "Write feeds/manifest.json — per-file records/bytes/sha256 for cache invalidation",
	Long: `manifest walks the data tree and writes feeds/manifest.json. Each entry
is sorted by path and includes a sha256 hash so consumers (port, mirrors,
integrity scripts) can do change detection against a single small file
instead of crawling the whole tree.

Run this after sync + generate so the manifest reflects the final state.
The manifest itself is excluded from the file list (chicken-and-egg), as
are dragnet's resume cursors in state/.`,
	RunE: runManifest,
}

func init() {
	manifestCmd.Flags().StringVar(&manifestRoot, "root", ".",
		"Path to the haul checkout (default: current dir)")
}

func runManifest(_ *cobra.Command, _ []string) error {
	m, err := manifest.Build(manifestRoot, version)
	if err != nil {
		return fmt.Errorf("build manifest: %w", err)
	}
	if err := manifest.Write(manifestRoot, m); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	log.Printf("[manifest] wrote feeds/manifest.json — %d files indexed", len(m.Files))
	return nil
}
