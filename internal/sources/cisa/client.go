// Package cisa fetches CISA's Known Exploited Vulnerabilities catalog.
//
// KEV is the authoritative US-government list of CVEs actively exploited in
// the wild — about 1,500 entries that turn over slowly. We always fetch the
// full catalog (it's only ~1.5 MB) and rely on MergeAll to dedupe. The
// `since` parameter is intentionally ignored so the catalog is always
// complete in haul, even on incremental syncs. The previous time-window
// filter caused sync to emit zero CISA incidents on first run.
package cisa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const (
	feedURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	maxBytes = 50 << 20 // current catalog ~1.5 MB; bound at 50 MiB
)

type Client struct {
	http *http.Client
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 60 * time.Second}}
}

func (c *Client) Name() string { return "cisa" }

func (c *Client) Fetch(ctx context.Context, _ time.Time) ([]*incident.Incident, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dragnet-bot/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("cisa kev status %d: %s", resp.StatusCode, b)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, fmt.Errorf("cisa kev: read body: %w", err)
	}

	var feed cisaFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("cisa kev: decode (%d bytes): %w", len(body), err)
	}
	log.Printf("[cisa] catalog has %d vulnerabilities (%d KB)", len(feed.Vulnerabilities), len(body)/1024)

	incidents := make([]*incident.Incident, 0, len(feed.Vulnerabilities))
	for i := range feed.Vulnerabilities {
		if inc := cisaVulnToIncident(&feed.Vulnerabilities[i]); inc != nil {
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
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
}

func cisaVulnToIncident(v *cisaVuln) *incident.Incident {
	if v.CVEID == "" {
		return nil
	}
	cw := incident.CompromiseWindow{}
	if t, err := time.Parse("2006-01-02", v.DateAdded); err == nil {
		cw.Start = t.UTC().Format(time.RFC3339)
	}

	inc := &incident.Incident{
		ID:               "cisa-" + strings.ToLower(strings.ReplaceAll(v.CVEID, "-", "")),
		Source:           "cisa",
		Description:      v.ShortDescription,
		AttackType:       "exploit",
		Severity:         "critical", // KEV = actively exploited
		CompromiseWindow: cw,
		CVEExt: &incident.CVEExtension{
			CVEID:           v.CVEID,
			ExploitedInWild: true,
		},
		References: []string{
			"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
			"https://nvd.nist.gov/vuln/detail/" + v.CVEID,
		},
	}

	// We deliberately do NOT attempt to map (vendor, product) onto a package
	// ecosystem here. CISA KEV is overwhelmingly enterprise software (Cisco,
	// Microsoft, BeyondTrust, F5, Citrix) that is never published as an npm/
	// pypi/cargo/etc package. The previous substring-based guesser produced
	// nonsense matches like "BeyondTrust" → cargo (because "trust" contains
	// "rust"). Cross-referencing with package-ecosystem advisories happens
	// downstream via CVE_ID matching in MergeAll.

	return inc
}
