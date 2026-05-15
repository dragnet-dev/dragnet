//go:build integration

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/dragnet-dev/dragnet/internal/sigma"
)

func TestIntegrationGenerateSigmaFromRealIncident(t *testing.T) {
	inc, err := incident.Load("../incidents/npm/npm-2026-001.yaml")
	if err != nil {
		t.Fatalf("load incident: %v", err)
	}

	outDir := t.TempDir()
	gen := sigma.New(outDir, "supply", nil)
	if err := gen.Generate(inc); err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Collect all generated files (generator writes into year subdirs).
	var generated []string
	for _, layer := range []string{"exposure", "ioc", "hunting"} {
		_ = filepath.Walk(filepath.Join(outDir, layer), func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				rel, _ := filepath.Rel(outDir, path)
				generated = append(generated, rel)
			}
			return nil
		})
	}
	t.Logf("Generated %d sigma files:", len(generated))
	for _, f := range generated {
		t.Logf("  %s", f)
	}

	if len(generated) == 0 {
		t.Error("no sigma files were generated")
	}

	// Core layers must have at least one file.
	for _, layer := range []string{"exposure", "ioc"} {
		var count int
		_ = filepath.Walk(filepath.Join(outDir, layer), func(_ string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				count++
			}
			return nil
		})
		if count == 0 {
			t.Errorf("no files generated in %s layer", layer)
		}
	}
}
