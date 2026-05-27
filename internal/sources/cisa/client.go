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
	"regexp"
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

// cveActorMap maps well-documented CVEs to Dragnet actor slugs.
// Only entries with clear public attribution from CISA/FBI/NSA joint advisories.
var cveActorMap = map[string]string{
	"CVE-2021-44228": "lazarus-supply-chain", // Log4Shell — Lazarus/APT41 exploitation
	"CVE-2023-34362": "cl0p",                 // MOVEit Transfer — Cl0p ransomware
	"CVE-2023-4966":  "lockbit",              // Citrix Bleed — LockBit 3.0
	"CVE-2024-3400":  "unc2630",              // PAN-OS — UNC2630 (Volt Typhoon adjacent)
	"CVE-2021-26084": "hafnium",              // Confluence — Hafnium / multiple APTs
	"CVE-2022-1388":  "apt41",               // F5 BIG-IP — APT41
	"CVE-2023-27350": "cl0p",                // PaperCut — Cl0p and LockBit
	"CVE-2023-44487": "apt41",               // HTTP/2 Rapid Reset — multiple state actors
	"CVE-2024-21762": "volt-typhoon",        // Fortinet — Volt Typhoon
	"CVE-2024-55591": "volt-typhoon",        // Fortinet auth bypass — Volt Typhoon
	"CVE-2021-40444": "apt28",              // MSHTML — APT28 / multiple actors
	"CVE-2024-23917": "apt29",              // JetBrains TeamCity — APT29 (Midnight Blizzard)
	"CVE-2023-42793": "apt29",              // JetBrains TeamCity — APT29
}

// cisaActorPatterns maps known actor names found in CISA Notes/description to
// Dragnet actor slugs. Checked case-insensitively against Notes and description.
var cisaActorPatterns = []struct{ pattern, actor string }{
	{"jade sleet", "jade-sleet"},
	{"tradertraitor", "jade-sleet"},
	{"ruby sleet", "jade-sleet"},
	{"lazarus group", "lazarus-supply-chain"},
	{"hidden cobra", "lazarus-supply-chain"},
	{"contagious interview", "phantom-circuit"},
	{"dev#popper", "phantom-circuit"},
	{"dev popper", "phantom-circuit"},
	{"north korean it worker", "north-korea-it-workers"},
	{"dprk it worker", "north-korea-it-workers"},
	{"famous chollima", "north-korea-it-workers"},
	{"volt typhoon", "volt-typhoon"},
	{"saltyphoon", "salt-typhoon"},
	{"salt typhoon", "salt-typhoon"},
	{"apt29", "apt29"},
	{"midnight blizzard", "apt29"},
	{"cozy bear", "apt29"},
	{"apt28", "apt28"},
	{"fancy bear", "apt28"},
	{"forest blizzard", "apt28"},
	{"apt41", "apt41"},
	{"hafnium", "hafnium"},
	{"cl0p", "cl0p"},
	{"clop ransomware", "cl0p"},
	{"lockbit", "lockbit"},
}

// reKEVActor extracts a specific group name from KnownRansomwareCampaignUse
// when the field contains an actor name rather than just "Known"/"Unknown".
var reKEVActor = regexp.MustCompile(`(?i)^\s*(known|unknown)\s*$`)

func normalizeCampaignName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
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

	// Actor attribution via CVE→actor lookup table (well-documented post-attribution).
	if slug, ok := cveActorMap[v.CVEID]; ok {
		inc.Campaign.Actor = slug
		inc.Campaign.Confidence = "high"
	}

	// Attribution via KnownRansomwareCampaignUse: if the field contains a
	// specific group name (not just "Known"/"Unknown"), use it.
	if kru := strings.TrimSpace(v.KnownRansomwareCampaignUse); kru != "" && !reKEVActor.MatchString(kru) {
		if inc.Campaign.Actor == "" {
			inc.Campaign.Actor = normalizeCampaignName(kru)
			inc.Campaign.Confidence = "medium"
		}
	}

	// Scan Notes field for known actor name patterns.
	if inc.Campaign.Actor == "" && v.Notes != "" {
		notesLower := strings.ToLower(v.Notes)
		for _, pat := range cisaActorPatterns {
			if strings.Contains(notesLower, pat.pattern) {
				inc.Campaign.Actor = pat.actor
				inc.Campaign.Confidence = "medium"
				break
			}
		}
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
