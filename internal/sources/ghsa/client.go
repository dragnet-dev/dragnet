package ghsa

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

const baseURL = "https://api.github.com/advisories"

type Client struct {
	http  *http.Client
	token string // optional GitHub token to raise rate limits
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 30 * time.Second}}
}

func NewWithToken(token string) *Client {
	return &Client{http: &http.Client{Timeout: 30 * time.Second}, token: token}
}

func (c *Client) Name() string { return "ghsa" }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	url := fmt.Sprintf("%s?type=malware&published=%s..%s&per_page=100",
		baseURL,
		since.UTC().Format("2006-01-02"),
		time.Now().UTC().Format("2006-01-02"),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ghsa status %d: %s", resp.StatusCode, b)
	}

	var advisories []ghsaAdvisory
	if err := json.NewDecoder(resp.Body).Decode(&advisories); err != nil {
		return nil, err
	}

	var incidents []*incident.Incident
	for i := range advisories {
		inc := ghsaToIncident(&advisories[i])
		if inc != nil {
			incidents = append(incidents, inc)
		}
	}
	return incidents, nil
}

type ghsaAdvisory struct {
	GHSAID          string    `json:"ghsa_id"`
	CVEID           string    `json:"cve_id"`
	Summary         string    `json:"summary"`
	Description     string    `json:"description"`
	Severity        string    `json:"severity"`
	PublishedAt     time.Time `json:"published_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	References      []string  `json:"references"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
	} `json:"vulnerabilities"`
}

func ghsaToIncident(a *ghsaAdvisory) *incident.Incident {
	if len(a.Vulnerabilities) == 0 {
		return nil
	}

	inc := &incident.Incident{
		GHSAID:      a.GHSAID,
		Description: a.Summary,
		AttackType:  "malicious_publish",
		Severity:    normaliseSeverity(a.Severity),
		References:  a.References,
	}

	for _, v := range a.Vulnerabilities {
		pkg := incident.Package{
			Name:      v.Package.Name,
			Ecosystem: normaliseEco(v.Package.Ecosystem),
		}
		if v.VulnerableVersionRange != "" {
			pkg.AffectedVersions = parseVersionRange(v.VulnerableVersionRange)
		}
		inc.Packages = append(inc.Packages, pkg)
	}

	if len(inc.Packages) > 0 {
		eco := inc.Packages[0].Ecosystem
		inc.ID = eco + "-ghsa-" + a.GHSAID
	}

	return inc
}

func normaliseSeverity(s string) string {
	switch s {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	default:
		return "low"
	}
}

// parseVersionRange splits a GHSA vulnerable_version_range string
// (">=1.0, <2.0" or "= 1.2.3") into individual constraint tokens.
func parseVersionRange(r string) []string {
	parts := strings.Split(r, ",")
	var out []string
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func normaliseEco(eco string) string {
	switch eco {
	case "npm":
		return "npm"
	case "pip", "PyPI":
		return "pypi"
	case "Rust", "crates.io":
		return "cargo"
	case "RubyGems":
		return "rubygems"
	case "NuGet":
		return "nuget"
	default:
		return eco
	}
}
