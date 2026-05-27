package ossf

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const (
	repoURL  = "https://github.com/ossf/malicious-packages"
	cacheDir = "state/ossf-cache"
)

type Client struct{}

func New() *Client { return &Client{} }

func (c *Client) Name() string { return "ossf" }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	dir := cacheDir
	if err := cloneOrPull(ctx, dir); err != nil {
		// If the clone was cancelled mid-flight the cache dir is half-populated;
		// remove it so the next run starts clean instead of trying to git-fetch
		// an inconsistent shallow clone.
		if ctx.Err() != nil {
			_ = os.RemoveAll(dir)
		}
		return nil, err
	}

	// Two-phase: collect file paths first (cheap walk), then parse in
	// parallel workers (the actual cost). 225k JSON parses at ~250µs each
	// is ~57s serial; on a 4-core runner with workers, ~15s.
	var paths []string
	visited := 0
	walkErr := filepath.WalkDir(filepath.Join(dir, "osv"), func(path string, d fs.DirEntry, err error) error {
		visited++
		if visited&0xff == 0 {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
		}
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers > len(paths) {
		workers = len(paths)
	}
	if workers < 1 {
		workers = 1
	}

	results := make([]*incident.Incident, len(paths))
	jobs := make(chan int, workers*2)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				data, err := os.ReadFile(paths[i])
				if err != nil {
					continue
				}
				var entry ossfEntry
				if err := json.Unmarshal(data, &entry); err != nil {
					continue
				}
				if entry.Modified.Before(since) {
					continue
				}
				results[i] = ossfToIncident(&entry)
			}
		}()
	}
	for i := range paths {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, ctx.Err()
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()

	incidents := make([]*incident.Incident, 0, len(results))
	for _, inc := range results {
		if inc != nil {
			incidents = append(incidents, inc)
		}
	}
	return incidents, nil
}

// cloneOrPull clones the OSSF repo on first run, then pulls the delta on subsequent runs.
// The cache persists in cacheDir so the 1.8 GB full clone only happens once.
func cloneOrPull(ctx context.Context, dir string) error {
	if _, err := os.Stat(filepath.Join(dir, ".git")); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return fmt.Errorf("ossf mkdir: %w", err)
		}
		cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", repoURL, dir)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("git clone ossf: %w", err)
		}
		return nil
	}
	// Shallow fetch + hard reset — avoids ff-only failures when the shallow history diverges.
	fetch := exec.CommandContext(ctx, "git", "-C", dir, "fetch", "--depth", "1", "origin")
	fetch.Stdout = os.Stderr
	fetch.Stderr = os.Stderr
	if err := fetch.Run(); err != nil {
		return fmt.Errorf("git fetch ossf: %w", err)
	}
	reset := exec.CommandContext(ctx, "git", "-C", dir, "reset", "--hard", "origin/main")
	reset.Stdout = os.Stderr
	reset.Stderr = os.Stderr
	if err := reset.Run(); err != nil {
		return fmt.Errorf("git reset ossf: %w", err)
	}
	return nil
}

type ossfEntry struct {
	ID        string    `json:"id"`
	Modified  time.Time `json:"modified"`
	Published time.Time `json:"published"`
	Summary   string    `json:"summary"`
	Details   string    `json:"details"`
	Affected  []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Versions []string `json:"versions"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

func ossfToIncident(e *ossfEntry) *incident.Incident {
	if len(e.Affected) == 0 {
		return nil
	}

	desc := e.Summary
	if desc == "" {
		if len(e.Affected) > 0 && e.Affected[0].Package.Name != "" {
			desc = "Malicious code in " + e.Affected[0].Package.Name + " (" + e.Affected[0].Package.Ecosystem + ")"
		} else {
			desc = "OSSF malware advisory " + e.ID
		}
	}
	inc := &incident.Incident{
		ID:          "ossf-" + strings.ToLower(strings.ReplaceAll(e.ID, "/", "-")),
		Description: desc,
		AttackType:  "malicious_publish",
		Severity:    "high",
	}

	for _, ref := range e.References {
		inc.References = append(inc.References, ref.URL)
	}

	for _, aff := range e.Affected {
		inc.Packages = append(inc.Packages, incident.Package{
			Name:             aff.Package.Name,
			Ecosystem:        normaliseEco(aff.Package.Ecosystem),
			AffectedVersions: aff.Versions,
		})
	}

	return inc
}

func normaliseEco(eco string) string {
	switch eco {
	case "PyPI":
		return "pypi"
	case "crates.io":
		return "cargo"
	default:
		return strings.ToLower(eco)
	}
}
