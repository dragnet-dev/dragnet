package ossf

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		return nil, err
	}

	var incidents []*incident.Incident
	err := filepath.WalkDir(filepath.Join(dir, "osv"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		var entry ossfEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil
		}

		if entry.Modified.Before(since) {
			return nil
		}

		inc := ossfToIncident(&entry)
		if inc != nil {
			incidents = append(incidents, inc)
		}
		return nil
	})
	return incidents, err
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

	inc := &incident.Incident{
		ID:          "ossf-" + strings.ToLower(strings.ReplaceAll(e.ID, "/", "-")),
		Description: e.Summary,
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
