package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/manifest"
	"github.com/spf13/cobra"
)

var (
	manifestRoot       string
	manifestSatellites []string
	manifestIndexOnly  bool
)

var manifestCmd = &cobra.Command{
	Use:   "manifest",
	Short: "Write feeds/manifest.json (and v0.1.11 index.json orchestrator)",
	Long: `manifest walks the data tree and writes feeds/manifest.json. Each entry
is sorted by path and includes a sha256 hash so consumers (port, mirrors,
integrity scripts) can do change detection against a single small file
instead of crawling the whole tree.

v0.1.11: pass --satellite name:path one or more times to include rule / STIX
satellite repos in the same manifest. Also writes index.json at the haul
root — a tiny orchestrator file consumers fetch first to discover all the
satellite raw-URL prefixes.

Run this after sync + generate so the manifest reflects the final state.`,
	SilenceUsage: true,
	RunE:         runManifest,
}

func init() {
	manifestCmd.Flags().StringVar(&manifestRoot, "root", ".",
		"Path to the haul checkout (default: current dir)")
	manifestCmd.Flags().StringSliceVar(&manifestSatellites, "satellite", nil,
		"name:path pair for a v0.1.11 satellite repo. Repeat the flag for each "+
			"(e.g. --satellite rules:/tmp/haul-rules --satellite stix:/tmp/haul-stix). "+
			"Files in each satellite are catalogued in the manifest with FileEntry.Repo "+
			"set to the satellite name.")
	manifestCmd.Flags().BoolVar(&manifestIndexOnly, "index-only", false,
		"Skip the file walk; only refresh index.json. Useful when the satellite "+
			"repos changed config but no data turned over.")
}

// IndexOrchestrator is the tiny entry-point file at haul/index.json. Consumers
// fetch this ONE URL to discover where every satellite lives and how to build
// raw-content URLs for its files. Keeps consumer code from hardcoding repo
// names — change the orchestrator, every consumer follows.
type IndexOrchestrator struct {
	SchemaVersion string            `json:"$schema_version"`
	Generated     string            `json:"generated"`
	Repos         map[string]string `json:"repos"`        // name -> github.com URL
	Raw           map[string]string `json:"raw"`          // name -> raw.githubusercontent.com prefix
	ManifestURL   string            `json:"manifest_url"` // canonical manifest location
}

func runManifest(_ *cobra.Command, _ []string) error {
	sats, err := parseSatellites(manifestSatellites)
	if err != nil {
		return err
	}

	if !manifestIndexOnly {
		m, err := manifest.BuildWithSatellites(manifestRoot, version, sats)
		if err != nil {
			return fmt.Errorf("build manifest: %w", err)
		}
		if err := manifest.Write(manifestRoot, m); err != nil {
			return fmt.Errorf("write manifest: %w", err)
		}
		repoSummary := countByRepo(m.Files)
		log.Printf("[manifest] wrote feeds/manifest.json — %d total file(s): %s",
			len(m.Files), repoSummary)
	}

	// Always (re)write the orchestrator file. It's tiny, only changes when
	// satellite roster changes, but writing it every run keeps the
	// generated timestamp honest.
	if err := writeOrchestrator(manifestRoot, sats); err != nil {
		return fmt.Errorf("write orchestrator: %w", err)
	}
	return nil
}

// parseSatellites converts "name:path" CLI args into Satellite structs.
// Validates the path exists; missing path is an error rather than a silent
// no-op so workflow misconfiguration surfaces immediately.
func parseSatellites(args []string) ([]manifest.Satellite, error) {
	out := make([]manifest.Satellite, 0, len(args))
	for _, a := range args {
		i := strings.IndexByte(a, ':')
		if i < 1 || i == len(a)-1 {
			return nil, fmt.Errorf("--satellite %q: expected name:path", a)
		}
		name := strings.TrimSpace(a[:i])
		path := strings.TrimSpace(a[i+1:])
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("--satellite %s: path %s: %w", name, path, err)
		}
		out = append(out, manifest.Satellite{Name: name, Root: path})
	}
	return out, nil
}

func countByRepo(files []manifest.FileEntry) string {
	counts := map[string]int{}
	for _, f := range files {
		key := f.Repo
		if key == "" {
			key = "intel"
		}
		counts[key]++
	}
	parts := make([]string, 0, len(counts))
	for k, v := range counts {
		parts = append(parts, fmt.Sprintf("%s=%d", k, v))
	}
	return strings.Join(parts, " ")
}

// writeOrchestrator emits {rootDir}/index.json. The repo + raw URLs are
// derived from the satellite names: every satellite is assumed to live at
// github.com/dragnet-dev/haul-{name} on main. If you ever fork the layout
// (different org, different branch), this is the place to change it.
func writeOrchestrator(rootDir string, sats []manifest.Satellite) error {
	const org = "dragnet-dev"
	const branch = "main"
	repos := map[string]string{
		"intel": fmt.Sprintf("https://github.com/%s/haul", org),
	}
	raw := map[string]string{
		"intel": fmt.Sprintf("https://raw.githubusercontent.com/%s/haul/%s", org, branch),
	}
	for _, s := range sats {
		repos[s.Name] = fmt.Sprintf("https://github.com/%s/haul-%s", org, s.Name)
		raw[s.Name] = fmt.Sprintf("https://raw.githubusercontent.com/%s/haul-%s/%s", org, s.Name, branch)
	}

	doc := IndexOrchestrator{
		SchemaVersion: manifest.SchemaVersion,
		Generated:     time.Now().UTC().Format(time.RFC3339),
		Repos:         repos,
		Raw:           raw,
		ManifestURL:   raw["intel"] + "/feeds/manifest.json",
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	dest := filepath.Join(rootDir, "index.json")
	return os.WriteFile(dest, data, 0o644)
}
