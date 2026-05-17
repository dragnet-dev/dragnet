// Package manifest builds a feeds/manifest.json artifact that lets downstream
// consumers (port, mirrors, integrity scripts) do cache invalidation and
// integrity checks against a single small file rather than walking the tree.
//
// One FileEntry per consumer-facing artifact, sorted by Path. The Files list
// is the only thing in the manifest — there's no BuiltAt timestamp, because
// the whole point is that re-running over unchanged data produces a byte-
// identical manifest. If we stamped time.Now() in there, the manifest's own
// sha256 would churn on every run and consumers couldn't tell what changed.
//
// Record counting:
//   .jsonl  → non-empty line count
//   .json   → top-level array length, or 1 if it's an object
//   .txt    → non-empty line count (matches IOC feed convention)
//   .yaml   → always 1
//
// Other extensions are silently skipped. Internal state files (state/last_sync.json,
// state/sigma-id-registry.json) and the manifest itself are also skipped.
package manifest

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FileEntry describes one consumer-facing artifact.
type FileEntry struct {
	Path    string `json:"path"`     // forward-slash, relative to root
	Records int    `json:"records"`  // 0 for empty .jsonl/.txt; 1 for .yaml
	Bytes   int64  `json:"bytes"`
	SHA256  string `json:"sha256"`
}

// Manifest is the top-level on-disk structure written to feeds/manifest.json.
type Manifest struct {
	DragnetVersion string      `json:"dragnet_version"`
	Files          []FileEntry `json:"files"`
}

var trackedExts = map[string]bool{
	".jsonl": true,
	".json":  true,
	".yaml":  true,
	".txt":   true,
}

// skipFiles are paths (rel to root, forward-slash) we intentionally omit.
// state/last_sync.json + state/sigma-id-registry.json are dragnet's resume
// cursors, not consumer data — they'd churn the manifest on every run.
// feeds/manifest.json is the chicken-and-egg case.
var skipFiles = map[string]bool{
	"state/last_sync.json":         true,
	"state/sigma-id-registry.json": true,
	"state/popular_models.json":    true,
	"feeds/manifest.json":          true,
}

// skipDirPrefixes are directory prefixes we never descend into.
//
// rules/sigma/ is excluded because including 200k+ per-rule entries would
// blow the manifest past GitHub's 50 MB single-file soft cap. Port doesn't
// cache-invalidate per-rule anyway; SIEM integrators pull the whole rules/
// tree as a unit. If we later want change-detection on rule sets, a single
// "rules/sigma/{module}.tar.gz" entry would do the job in one line.
var skipDirPrefixes = []string{
	".git/", ".github/",
	"state/ossf-cache/",
	"state/trivy_cache/",
}

// skipRelPathSubstrings — file path contains any of these → skip.
var skipRelPathSubstrings = []string{
	"/rules/sigma/",
}

// Build walks rootDir, returns Manifest with sorted Files.
func Build(rootDir, version string) (*Manifest, error) {
	var files []FileEntry

	err := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(rootDir, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			// Skip dot-dirs and known cache/state dirs early to avoid scanning them.
			base := d.Name()
			if base != "." && strings.HasPrefix(base, ".") {
				return filepath.SkipDir
			}
			for _, p := range skipDirPrefixes {
				if rel+"/" == p || strings.HasPrefix(rel+"/", p) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if skipFiles[rel] {
			return nil
		}
		for _, s := range skipRelPathSubstrings {
			if strings.Contains("/"+rel, s) {
				return nil
			}
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !trackedExts[ext] {
			return nil
		}
		entry, err := buildEntry(path, rel, ext)
		if err != nil {
			return fmt.Errorf("manifest %s: %w", rel, err)
		}
		files = append(files, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return &Manifest{DragnetVersion: version, Files: files}, nil
}

func buildEntry(absPath, relPath, ext string) (FileEntry, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return FileEntry{}, err
	}
	sum, err := hashFile(absPath)
	if err != nil {
		return FileEntry{}, err
	}
	records, err := countRecords(absPath, ext)
	if err != nil {
		// Non-fatal — record as 1 and move on. The hash still tells consumers
		// what changed; we don't want one corrupt JSON file to fail the whole
		// build.
		records = 1
	}
	return FileEntry{
		Path:    relPath,
		Records: records,
		Bytes:   info.Size(),
		SHA256:  sum,
	}, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func countRecords(path, ext string) (int, error) {
	switch ext {
	case ".yaml":
		return 1, nil
	case ".jsonl", ".txt":
		return countNonEmptyLines(path)
	case ".json":
		return countJSON(path)
	}
	return 1, nil
}

func countNonEmptyLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	// Allow long lines (JSONL records can be hundreds of KB for trivy CVEs
	// with dozens of AffectedImages).
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	n := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			n++
		}
	}
	return n, scanner.Err()
}

func countJSON(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err == nil {
		return len(arr), nil
	}
	// Otherwise it's an object (or invalid) — treat as one logical record.
	return 1, nil
}

// Write serializes m to {rootDir}/feeds/manifest.json atomically.
func Write(rootDir string, m *Manifest) error {
	dir := filepath.Join(rootDir, "feeds")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	dest := filepath.Join(dir, "manifest.json")
	tmp := dest + ".tmp"

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}
