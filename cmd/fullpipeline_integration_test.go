//go:build integration

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/backends"
	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/dragnet-dev/dragnet/internal/sigma"
)

func TestIntegrationFullPipeline(t *testing.T) {
	// Step 1: Load a real incident
	inc, err := incident.Load("../incidents/npm/npm-2026-001.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Step 2: Generate Sigma rules
	sigmaDir := filepath.Join(t.TempDir(), "sigma")
	gen := sigma.New(sigmaDir, "supply", nil)
	if err := gen.Generate(inc); err != nil {
		t.Fatalf("sigma generate: %v", err)
	}

	// Step 3: Compile each Sigma rule through KQL and Sentinel backends.
	// Walk layer dirs recursively to account for year subdirectories.
	be := backends.All("detect")
	var sigmaFiles []string
	for _, layer := range []string{"exposure", "ioc", "hunting"} {
		_ = filepath.Walk(filepath.Join(sigmaDir, layer), func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && strings.HasSuffix(path, ".yaml") {
				sigmaFiles = append(sigmaFiles, path)
			}
			return nil
		})
	}

	if len(sigmaFiles) == 0 {
		t.Fatal("no sigma files to compile")
	}

	for _, sf := range sigmaFiles {
		data, err := os.ReadFile(sf)
		if err != nil {
			t.Errorf("read %s: %v", sf, err)
			continue
		}
		for _, b := range be {
			out, err := b.Compile(data)
			if err != nil {
				t.Errorf("backend %s compile %s: %v", b.Name(), filepath.Base(sf), err)
				continue
			}
			if len(out) == 0 {
				t.Errorf("backend %s produced empty output for %s", b.Name(), filepath.Base(sf))
			}
		}
	}

	t.Logf("Full pipeline OK: %d sigma files × %d backends", len(sigmaFiles), len(be))
}
