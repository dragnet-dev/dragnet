// Package trivy_db queries the Trivy vulnerability database for OS-package CVEs.
//
// We bypass the trivy-db Go library's helper APIs because its
// ForEachVulnerabilityID looks for a "vulnerability-id" bucket that no longer
// exists in the published Trivy DB schema (schema 2). Instead we iterate the
// bbolt DB directly:
//
//   {OS}{space}{version} → bucket (e.g. "alpine 3.20", "debian 12")
//     {package-name}     → sub-bucket
//       {CVE-ID}         → leaf value: {"FixedVersion": "..."}
//
//   "vulnerability"      → bucket of CVE-ID → {CVSS, Description, References, ...}
//
// One Trivy "advisory" = one (OS-version, package, CVE) triple. We aggregate
// these into one incident per CVE so port/buoy can ask "which images are
// affected by CVE-X?" with a single lookup.
package trivy_db

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.etcd.io/bbolt"

	"github.com/dragnet-dev/dragnet/internal/container"
	"github.com/dragnet-dev/dragnet/internal/incident"
)

// Bucket-name prefixes we treat as OS-version sources. Match is case-insensitive
// prefix-only so future versions ("alpine 3.23", "debian 13") land automatically
// when Aqua adds them.
var osPrefixes = []string{
	"alpine ",
	"debian ",
	"ubuntu ",
	"amazon linux",
	"red hat",
	"oracle linux",
	"rocky linux",
	"alma ",
	"suse linux enterprise",
	"photon os",
	"azure linux",
	"cbl-mariner",
	"wolfi",
	"chainguard",
}

// Bucket containing CVE-ID -> {CVSS, Description, References, ...} metadata.
const vulnBucket = "vulnerability"

type Client struct {
	cacheDir      string
	popularImages []container.PopularImage
}

func New(cacheDir string, popularImages []container.PopularImage) *Client {
	return &Client{cacheDir: cacheDir, popularImages: popularImages}
}

func (c *Client) Name() string { return "trivy_db" }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	if err := os.MkdirAll(c.cacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("trivy_db: mkdir cache: %w", err)
	}
	if err := c.download(ctx); err != nil {
		return nil, fmt.Errorf("trivy_db: download: %w", err)
	}

	dbPath := filepath.Join(c.cacheDir, "db", "trivy.db")
	db, err := bbolt.Open(dbPath, 0o600, &bbolt.Options{
		ReadOnly: true,
		Timeout:  10 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("trivy_db: open %s: %w", dbPath, err)
	}
	defer db.Close()

	// agg[cveID] accumulates every (OS, package) affected by that CVE.
	type osPkg struct {
		family       string // e.g. "alpine"
		version      string // e.g. "3.20"
		pkg          string
		fixedVersion string
	}
	agg := map[string][]osPkg{}

	err = db.View(func(tx *bbolt.Tx) error {
		return tx.ForEach(func(bucketName []byte, osBucket *bbolt.Bucket) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := string(bucketName)
			lower := strings.ToLower(name)
			if !isOSBucket(lower) {
				return nil
			}
			family, version := splitFamilyVersion(name)
			return osBucket.ForEach(func(pkgName, val []byte) error {
				if val != nil {
					return nil // not a sub-bucket
				}
				pkgBucket := osBucket.Bucket(pkgName)
				if pkgBucket == nil {
					return nil
				}
				pkg := string(pkgName)
				return pkgBucket.ForEach(func(cveID, advJSON []byte) error {
					fixed := ""
					var adv struct{ FixedVersion string }
					if err := json.Unmarshal(advJSON, &adv); err == nil {
						fixed = adv.FixedVersion
					}
					agg[string(cveID)] = append(agg[string(cveID)], osPkg{
						family: family, version: version, pkg: pkg, fixedVersion: fixed,
					})
					return nil
				})
			})
		})
	})
	if err != nil {
		return nil, fmt.Errorf("trivy_db: walk DB: %w", err)
	}
	log.Printf("[trivy_db] aggregated advisories for %d distinct CVEs", len(agg))

	// Stable iteration so the resulting incident IDs are deterministic.
	cveIDs := make([]string, 0, len(agg))
	for k := range agg {
		cveIDs = append(cveIDs, k)
	}
	sort.Strings(cveIDs)

	var incidents []*incident.Incident
	err = db.View(func(tx *bbolt.Tx) error {
		vb := tx.Bucket([]byte(vulnBucket))
		if vb == nil {
			return fmt.Errorf("no %q bucket in DB", vulnBucket)
		}
		for _, cveID := range cveIDs {
			if err := ctx.Err(); err != nil {
				return err
			}
			meta := vb.Get([]byte(cveID))
			vuln := parseVuln(meta) // empty struct if meta nil

			if !since.IsZero() && !vuln.LastModified.IsZero() && vuln.LastModified.Before(since) {
				continue
			}

			var affected []incident.AffectedImage
			byRepo := map[string]*incident.AffectedImage{}
			for _, op := range agg[cveID] {
				repo := familyToDockerRepo(op.family)
				if _, ok := byRepo[repo]; !ok {
					byRepo[repo] = &incident.AffectedImage{
						Repository: repo,
						OSFamily:   op.family,
						CVEIDs:     []string{cveID},
					}
				}
				tag := op.version
				if !contains(byRepo[repo].VulnerableTags, tag) {
					byRepo[repo].VulnerableTags = append(byRepo[repo].VulnerableTags, tag)
				}
			}
			// Sort tags for deterministic output
			for _, img := range byRepo {
				sort.Strings(img.VulnerableTags)
				affected = append(affected, *img)
			}
			sort.Slice(affected, func(i, j int) bool { return affected[i].Repository < affected[j].Repository })

			if len(c.popularImages) > 0 && !container.AffectsPopular(affected, c.popularImages, 0) {
				continue
			}

			// Populate CompromiseWindow from the CVE's last-modified date so
			// the canonical ID assigner can year-bucket properly and consumers
			// can sort/filter by published. Without this, every Trivy record
			// fell into the "no date" bucket and got dragnet-container-2026-N
			// regardless of when the underlying CVE was disclosed.
			cw := incident.CompromiseWindow{}
			if !vuln.LastModified.IsZero() {
				cw.Start = vuln.LastModified.UTC().Format(time.RFC3339)
			}

			// Surface repo:tag pairs as FileName indicators so this CVE shows
			// up in feeds/unified.{json,jsonl} alongside conventional IOCs.
			// Consumers (port search, dredge check) can then answer "is
			// image X:Y vulnerable?" against the unified feed instead of
			// needing the container/incidents/all/ shards. Capped per
			// incident to avoid the (rare) Trivy record affecting 500+
			// tags blowing up the feeds.
			const maxImageIndicators = 50
			var imageIndicators []string
			for _, img := range affected {
				for _, tag := range img.VulnerableTags {
					imageIndicators = append(imageIndicators, img.Repository+":"+tag)
					if len(imageIndicators) >= maxImageIndicators {
						break
					}
				}
				if len(imageIndicators) >= maxImageIndicators {
					break
				}
			}

			inc := &incident.Incident{
				ID:               "trivy-" + strings.ToLower(strings.ReplaceAll(cveID, "-", "")),
				Source:           "trivy_db",
				AttackType:       "vulnerability",
				Severity:         vuln.Severity,
				Description:      vuln.Description,
				References:       vuln.References,
				CompromiseWindow: cw,
				Indicators: incident.Indicators{
					FileNames: imageIndicators,
				},
				CVEExt: &incident.CVEExtension{
					CVEID:      cveID,
					CVSSScore:  vuln.CVSS,
					CVSSVector: vuln.CVSSVector,
				},
				ContainerExt: &incident.ContainerExtension{
					AffectedImages: affected,
					// Mirror the CVSS into ContainerExt so the container
					// module's tier-based filter (Tier 2 = CVSS ≥ 9.0,
					// Tier 3 = CVSS ≥ 7.0 + PoC) actually sees a score.
					CVSS: vuln.CVSS,
				},
			}
			incidents = append(incidents, inc)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("trivy_db: enrich: %w", err)
	}

	log.Printf("[trivy_db] returning %d incidents", len(incidents))
	return incidents, nil
}

type parsedVuln struct {
	CVSS         float64
	CVSSVector   string
	Description  string
	References   []string
	Severity     string
	LastModified time.Time
}

func parseVuln(meta []byte) parsedVuln {
	if len(meta) == 0 {
		return parsedVuln{Severity: "unknown"}
	}
	var raw struct {
		Description    string
		References     []string
		Severity       string
		LastModifiedDate *time.Time
		CVSS           map[string]struct {
			V3Score  float64
			V3Vector string
			V2Score  float64
			V2Vector string
		}
	}
	if err := json.Unmarshal(meta, &raw); err != nil {
		return parsedVuln{Severity: "unknown"}
	}
	p := parsedVuln{
		Description: raw.Description,
		References:  raw.References,
		Severity:    normaliseSeverity(raw.Severity),
	}
	if raw.LastModifiedDate != nil {
		p.LastModified = *raw.LastModifiedDate
	}
	// Prefer the highest v3 score across sources (nvd, redhat, etc.).
	for _, c := range raw.CVSS {
		if c.V3Score > p.CVSS {
			p.CVSS = c.V3Score
			p.CVSSVector = c.V3Vector
		}
	}
	if p.CVSS == 0 {
		for _, c := range raw.CVSS {
			if c.V2Score > p.CVSS {
				p.CVSS = c.V2Score
				p.CVSSVector = c.V2Vector
			}
		}
	}
	return p
}

func normaliseSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "unknown"
	}
}

func isOSBucket(lowerName string) bool {
	for _, p := range osPrefixes {
		if strings.HasPrefix(lowerName, p) {
			return true
		}
	}
	return false
}

// splitFamilyVersion splits "alpine 3.20" → ("alpine", "3.20").
func splitFamilyVersion(name string) (family, version string) {
	idx := strings.LastIndex(name, " ")
	if idx < 0 {
		return strings.ToLower(name), ""
	}
	tail := name[idx+1:]
	// If tail starts with a digit treat it as version; otherwise the whole
	// name is the family ("Red Hat CPE", "Wolfi").
	if len(tail) > 0 && (tail[0] >= '0' && tail[0] <= '9') {
		return strings.ToLower(name[:idx]), tail
	}
	return strings.ToLower(name), ""
}

// familyToDockerRepo maps a Trivy OS-family name to its common Docker Hub repo.
func familyToDockerRepo(family string) string {
	switch strings.ToLower(family) {
	case "alpine":
		return "alpine"
	case "debian":
		return "debian"
	case "ubuntu":
		return "ubuntu"
	case "red hat", "redhat":
		return "redhat/ubi9"
	case "oracle linux":
		return "oraclelinux"
	case "rocky linux":
		return "rockylinux"
	case "alma":
		return "almalinux"
	case "amazon linux":
		return "amazonlinux"
	default:
		return family
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// download runs trivy with --download-db-only to refresh the local DB cache.
func (c *Client) download(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "trivy", "image", "--download-db-only", "--cache-dir", c.cacheDir)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("trivy image --download-db-only: %w", err)
	}
	return nil
}
