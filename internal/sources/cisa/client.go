package cisa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const feedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type Client struct {
	http *http.Client
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) Name() string { return "cisa" }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
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
		return nil, fmt.Errorf("cisa kev status %d: %s", resp.StatusCode, b)
	}

	var feed cisaFeed
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, err
	}

	var incidents []*incident.Incident
	for i := range feed.Vulnerabilities {
		v := &feed.Vulnerabilities[i]
		added, err := time.Parse("2006-01-02", v.DateAdded)
		if err != nil {
			continue
		}
		if added.Before(since) {
			continue
		}
		inc := cisaVulnToIncident(v)
		if inc != nil {
			incidents = append(incidents, inc)
		}
	}
	return incidents, nil
}

type cisaFeed struct {
	Title           string     `json:"title"`
	Vulnerabilities []cisaVuln `json:"vulnerabilities"`
}

type cisaVuln struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	Notes             string `json:"notes"`
}

func cisaVulnToIncident(v *cisaVuln) *incident.Incident {
	inc := &incident.Incident{
		ID:          "cisa-" + strings.ToLower(strings.ReplaceAll(v.CVEID, "-", "")),
		Description: v.ShortDescription,
		AttackType:  "exploit",
		Severity:    "critical", // CISA KEV = actively exploited = critical
		References: []string{
			"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
		},
	}

	if eco := guessEcosystem(v.VendorProject, v.Product); eco != "" {
		inc.Packages = append(inc.Packages, incident.Package{
			Name:      v.Product,
			Ecosystem: eco,
		})
	}

	return inc
}

var ecosystemKeywords = map[string][]string{
	"npm":      {"node", "nodejs", "npm", "javascript", "js"},
	"pypi":     {"python", "pip", "pypi"},
	"cargo":    {"rust", "cargo", "crates"},
	"rubygems": {"ruby", "gem", "rails"},
	"nuget":    {"nuget", ".net", "dotnet"},
}

func guessEcosystem(vendor, product string) string {
	combined := strings.ToLower(vendor + " " + product)
	for eco, keywords := range ecosystemKeywords {
		for _, kw := range keywords {
			if strings.Contains(combined, kw) {
				return eco
			}
		}
	}
	return ""
}
