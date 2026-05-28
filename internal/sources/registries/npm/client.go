package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/httpclient"
	"github.com/dragnet-dev/dragnet/internal/incident"
)

// changesURL is the CouchDB continuous changes feed for npm.
const changesURL = "https://replicate.npmjs.com/_changes"

// anomaly thresholds
const (
	minDownloadsForNewMaintainerAlert = 10_000
	sizeSpikeBytes                    = 500 * 1024 // 500KB
)

var suspiciousHooks = []string{"preinstall", "postinstall", "prepare"}

type Client struct {
	http    *http.Client
	lastSeq int64
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 60 * time.Second, Transport: httpclient.New()}}
}

func NewWithSeq(lastSeq int64) *Client {
	c := New()
	c.lastSeq = lastSeq
	return c
}

func (c *Client) Name() string { return "npm_registry" }

func (c *Client) Fetch(ctx context.Context, _ time.Time) ([]*incident.Incident, error) {
	url := fmt.Sprintf("%s?since=%d&limit=500", changesURL, c.lastSeq)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("npm changes status %d: %s", resp.StatusCode, b)
	}

	var feed npmChangesFeed
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, err
	}

	var incidents []*incident.Incident
	for _, change := range feed.Results {
		inc := c.analyseChange(ctx, &change)
		if inc != nil {
			incidents = append(incidents, inc)
		}
		if change.Seq > c.lastSeq {
			c.lastSeq = change.Seq
		}
	}
	return incidents, nil
}

// LastSeq returns the last processed sequence number for state persistence.
func (c *Client) LastSeq() int64 { return c.lastSeq }

type npmChangesFeed struct {
	Results []npmChange `json:"results"`
	LastSeq int64       `json:"last_seq"`
}

type npmChange struct {
	Seq int64   `json:"seq"`
	ID  string  `json:"id"`
	Doc *npmDoc `json:"doc"`
}

type npmDoc struct {
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Maintainers []npmMaintainer       `json:"maintainers"`
	Versions    map[string]npmVersion `json:"versions"`
	DistTags    map[string]string     `json:"dist-tags"`
	Time        map[string]string     `json:"time"`
}

type npmMaintainer struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type npmVersion struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`
	Dist    struct {
		UnpackedSize int64  `json:"unpackedSize"`
		Shasum       string `json:"shasum"`
	} `json:"dist"`
}

func (c *Client) analyseChange(ctx context.Context, change *npmChange) *incident.Incident {
	if change.Doc == nil {
		return nil
	}
	doc := change.Doc
	latest := doc.DistTags["latest"]
	if latest == "" {
		return nil
	}
	ver, ok := doc.Versions[latest]
	if !ok {
		return nil
	}

	var anomalies []string

	// Check for suspicious install hooks
	for _, hook := range suspiciousHooks {
		if script, ok := ver.Scripts[hook]; ok && script != "" {
			anomalies = append(anomalies, fmt.Sprintf("suspicious %s script: %s", hook, truncate(script, 80)))
		}
	}

	// Check for large package size spike (compare against previous version)
	if ver.Dist.UnpackedSize > sizeSpikeBytes {
		prev := previousVersion(doc, latest)
		if prev != nil && prev.Dist.UnpackedSize > 0 {
			ratio := float64(ver.Dist.UnpackedSize) / float64(prev.Dist.UnpackedSize)
			if ratio > 3.0 {
				anomalies = append(anomalies, fmt.Sprintf("size spike: %d bytes (%.1fx previous)", ver.Dist.UnpackedSize, ratio))
			}
		}
	}

	if len(anomalies) == 0 {
		return nil
	}

	log.Printf("[npm] anomalies in %s@%s: %s", doc.Name, latest, strings.Join(anomalies, "; "))

	return &incident.Incident{
		ID:          fmt.Sprintf("npm-draft-%s-%s", sanitizeID(doc.Name), sanitizeID(latest)),
		Description: fmt.Sprintf("Anomalous publish detected: %s@%s — %s", doc.Name, latest, strings.Join(anomalies, "; ")),
		AttackType:  "malicious_publish",
		Severity:    "medium",
		References: []string{
			"https://www.npmjs.com/package/" + doc.Name,
		},
		Packages: []incident.Package{
			{Name: doc.Name, Ecosystem: "npm", AffectedVersions: []string{latest}},
		},
	}
}

func previousVersion(doc *npmDoc, latest string) *npmVersion {
	// Find the most recent version that isn't latest
	var prevTime time.Time
	var prev *npmVersion
	for ver, published := range doc.Time {
		if ver == latest || ver == "created" || ver == "modified" {
			continue
		}
		t, err := time.Parse(time.RFC3339, published)
		if err != nil {
			continue
		}
		if t.After(prevTime) {
			if v, ok := doc.Versions[ver]; ok {
				prev = &v
				prevTime = t
			}
		}
	}
	return prev
}

func sanitizeID(s string) string {
	s = strings.ReplaceAll(s, "@", "")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ".", "-")
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
