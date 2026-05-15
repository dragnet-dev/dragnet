package vulncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const kevURL = "https://api.vulncheck.com/v3/index/vulncheck-kev"

type Client struct {
	http *http.Client
}

func New() *Client { return &Client{http: &http.Client{Timeout: 30 * time.Second}} }

func (c *Client) Name() string { return "vulncheck" }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dragnet/1.0")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vulncheck status %d: %s", resp.StatusCode, b)
	}
	var r struct {
		Data []struct {
			CVEID             string    `json:"cveID"`
			VendorProject     string    `json:"vendorProject"`
			Product           string    `json:"product"`
			VulnerabilityName string    `json:"vulnerabilityName"`
			DateAdded         time.Time `json:"dateAdded"`
			CVSS              float64   `json:"cvss"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	var incidents []*incident.Incident
	for _, entry := range r.Data {
		if entry.DateAdded.Before(since) {
			continue
		}
		inc := &incident.Incident{
			ID:          fmt.Sprintf("vulncheck-%s", sanitize(entry.CVEID)),
			Description: fmt.Sprintf("%s: %s %s", entry.CVEID, entry.VendorProject, entry.VulnerabilityName),
			AttackType:  "vulnerability",
			Severity:    cvssToSeverity(entry.CVSS),
			References:  []string{fmt.Sprintf("https://vulncheck.com/advisories/%s", entry.CVEID)},
			CVEExt: &incident.CVEExtension{
				CVEID:           entry.CVEID,
				CVSSScore:       entry.CVSS,
				ExploitedInWild: true,
				AffectedSoftware: []incident.AffectedSoftware{
					{Vendor: entry.VendorProject, Product: entry.Product},
				},
			},
		}
		incidents = append(incidents, inc)
	}
	return incidents, nil
}

func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

func sanitize(s string) string {
	var b []byte
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			b = append(b, c)
		} else if c >= 'A' && c <= 'Z' {
			b = append(b, c+32)
		} else {
			b = append(b, '-')
		}
	}
	return string(b)
}
