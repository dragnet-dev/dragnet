package trivy_db

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	"go.etcd.io/bbolt"

	"github.com/dragnet-dev/dragnet/internal/container"
	"github.com/dragnet-dev/dragnet/internal/incident"
)

const trivyDBImage = "ghcr.io/aquasecurity/trivy-db:2"

// osFamilies are the OS sources queried from the Trivy DB.
var osFamilies = []string{"alpine", "debian", "ubuntu", "amazon", "redhat"}

// Client downloads and queries the Trivy vulnerability database.
// Requires the trivy binary to be installed on PATH.
type Client struct {
	cacheDir      string // e.g. state/trivy_cache — must already exist
	popularImages []container.PopularImage
}

// New creates a Trivy DB source. popularImages is used to filter CVEs to those
// affecting images with sufficient pull counts; pass nil to skip the filter.
func New(cacheDir string, popularImages []container.PopularImage) *Client {
	return &Client{cacheDir: cacheDir, popularImages: popularImages}
}

func (c *Client) Name() string { return "trivy_db" }

// Fetch downloads (or reuses cached) Trivy DB, iterates vulnerability IDs, and
// returns incidents for CVEs published/modified after `since` that affect OS
// packages present in popular base images.
func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	if err := os.MkdirAll(c.cacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("trivy_db: mkdir cache: %w", err)
	}
	if err := c.download(ctx); err != nil {
		return nil, fmt.Errorf("trivy_db: download: %w", err)
	}

	dbDir := filepath.Join(c.cacheDir, "db")
	if err := trivydb.Init(dbDir); err != nil {
		return nil, fmt.Errorf("trivy_db: init db: %w", err)
	}
	defer trivydb.Close()

	dbc := trivydb.Config{}

	var incidents []*incident.Incident

	err := dbc.ForEachVulnerabilityID(func(_ *bbolt.Tx, cveID string) error {
		vuln, err := dbc.GetVulnerability(cveID)
		if err != nil {
			return nil // non-fatal: skip unparseable entries
		}

		// Filter by modification date so incremental syncs don't re-process old entries.
		if vuln.LastModifiedDate != nil && vuln.LastModifiedDate.Before(since) {
			return nil
		}

		// Extract best CVSS score (prefer v3, fall back to v2).
		cvss := bestCVSS(vuln.CVSS)

		// Query OS advisories for this CVE across all tracked families.
		var affected []incident.AffectedImage
		for _, family := range osFamilies {
			advisories, err := dbc.GetAdvisories(family, cveID)
			if err != nil || len(advisories) == 0 {
				continue
			}
			imgs := advisoriesToImages(cveID, family, advisories)
			affected = append(affected, imgs...)
		}
		if len(affected) == 0 {
			return nil
		}

		// Optionally filter to images that have sufficient pull counts.
		if len(c.popularImages) > 0 && !container.AffectsPopular(affected, c.popularImages, 0) {
			return nil
		}

		inc := mapToIncident(cveID, cvss, vuln, affected)
		incidents = append(incidents, inc)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("trivy_db: iterate: %w", err)
	}

	log.Printf("[trivy_db] found %d container CVE incidents", len(incidents))
	return incidents, nil
}

// download runs trivy with --download-db-only to refresh the local DB cache.
func (c *Client) download(ctx context.Context) error {
	cmd := exec.CommandContext(ctx,
		"trivy", "image",
		"--download-db-only",
		"--cache-dir", c.cacheDir,
	)
	cmd.Stdout = os.Stderr // log trivy progress to stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("trivy image --download-db-only: %w", err)
	}
	return nil
}
