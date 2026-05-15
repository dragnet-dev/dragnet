package eol_date

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const apiBase = "https://endoflife.date/api"

var officialProducts = []string{
	"nodejs", "python", "ruby", "php", "go", "java",
	"ubuntu", "debian", "alpine", "nginx", "mysql", "postgresql", "redis",
}

// EOLEntry is one release-cycle record from endoflife.date.
type EOLEntry struct {
	Cycle   string `json:"cycle"`
	EOL     string `json:"eol"`     // date "2023-09-11" or false
	Latest  string `json:"latest"`
	LTS     bool   `json:"lts"`
}

type Client struct {
	http *http.Client
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) Name() string { return "eol_date" }

// Fetch satisfies the sources.Source interface. It fetches all EOL data and
// returns one incident per product cycle that has already passed end-of-life.
// The `since` parameter filters by EOL date so reruns don't re-emit stale entries.
func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	data, err := c.FetchAll(ctx)
	if err != nil {
		return nil, err
	}

	var incidents []*incident.Incident
	for product, entries := range data {
		for _, e := range entries {
			if e.EOL == "" || e.EOL == "false" {
				continue
			}
			eolDate, err := time.Parse("2006-01-02", e.EOL)
			if err != nil || !time.Now().After(eolDate) {
				continue
			}
			// Only emit if EOL date is after `since` (new-to-us in this window)
			if !eolDate.After(since) {
				continue
			}
			inc := eolToIncident(product, e)
			incidents = append(incidents, inc)
		}
	}
	return incidents, nil
}

// eolToIncident maps a product+cycle that is past EOL into a Dragnet incident.
func eolToIncident(product string, e EOLEntry) *incident.Incident {
	repo := productToRepo(product)
	year := e.EOL[:4]
	// Provisional ID — overwritten by registry at merge time.
	id := fmt.Sprintf("container-eol-%s-%s-0000", strings.ToLower(product), year)

	return &incident.Incident{
		ID:          id,
		Source:      "eol_date",
		AttackType:  "eol",
		Severity:    "high",
		Description: fmt.Sprintf("%s %s reached end-of-life on %s. All images based on this cycle are permanently unpatched.", product, e.Cycle, e.EOL),
		References:  []string{fmt.Sprintf("https://endoflife.date/%s", product)},
		CompromiseWindow: incident.CompromiseWindow{
			Start: e.EOL + "T00:00:00Z",
		},
		ContainerExt: &incident.ContainerExtension{
			EOLImages: []incident.EOLImageInfo{
				{
					Repository: repo,
					Cycle:      e.Cycle,
					EOLDate:    e.EOL,
				},
			},
			Tier: 2,
		},
	}
}

// productToRepo maps endoflife.date product names to Docker Hub repository names.
func productToRepo(product string) string {
	m := map[string]string{
		"nodejs":     "node",
		"python":     "python",
		"ruby":       "ruby",
		"php":        "php",
		"go":         "golang",
		"java":       "openjdk",
		"ubuntu":     "ubuntu",
		"debian":     "debian",
		"alpine":     "alpine",
		"nginx":      "nginx",
		"mysql":      "mysql",
		"postgresql": "postgres",
		"redis":      "redis",
	}
	if r, ok := m[product]; ok {
		return r
	}
	return product
}

// FetchAll retrieves EOL data for all tracked products.
func (c *Client) FetchAll(ctx context.Context) (map[string][]EOLEntry, error) {
	result := make(map[string][]EOLEntry, len(officialProducts))
	for _, product := range officialProducts {
		entries, err := c.fetch(ctx, product)
		if err != nil {
			// Non-fatal: log and continue so one failed product doesn't abort.
			continue
		}
		result[product] = entries
	}
	return result, nil
}

func (c *Client) fetch(ctx context.Context, product string) ([]EOLEntry, error) {
	url := fmt.Sprintf("%s/%s.json", apiBase, product)
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
		return nil, fmt.Errorf("eol_date: %s: status %d", product, resp.StatusCode)
	}
	var entries []EOLEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("eol_date: %s: decode: %w", product, err)
	}
	return entries, nil
}

// IsEOL reports whether the given product version has passed end-of-life.
// Returns (true, "2023-09-11") or (false, "").
func IsEOL(product, version string, data map[string][]EOLEntry) (bool, string) {
	entries, ok := data[product]
	if !ok {
		return false, ""
	}
	cycle := extractCycle(version)
	for _, e := range entries {
		if e.Cycle != cycle {
			continue
		}
		if e.EOL == "" || e.EOL == "false" {
			return false, ""
		}
		eolDate, err := time.Parse("2006-01-02", e.EOL)
		if err != nil {
			continue
		}
		return time.Now().After(eolDate), e.EOL
	}
	return false, ""
}

// extractCycle returns the major version portion used as the cycle key.
// "18.10.0" → "18",  "3.11.4" → "3.11",  "22.04" → "22.04"
func extractCycle(version string) string {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return parts[0]
}
