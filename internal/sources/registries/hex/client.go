package hex

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

type Client struct {
	http          *http.Client
	lastUpdatedAt string
}

func New() *Client                       { return &Client{http: &http.Client{Timeout: 30 * time.Second, Transport: httpclient.New()}} }
func NewWithUpdatedAt(ts string) *Client { c := New(); c.lastUpdatedAt = ts; return c }

func (c *Client) Name() string          { return "hex" }
func (c *Client) LastUpdatedAt() string { return c.lastUpdatedAt }

func (c *Client) Fetch(ctx context.Context, _ time.Time) ([]*incident.Incident, error) {
	url := "https://hex.pm/api/packages?sort=updated_at&page=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hex status %d: %s", resp.StatusCode, b)
	}

	var pkgs []struct {
		Name      string `json:"name"`
		UpdatedAt string `json:"updated_at"`
		Releases  []struct {
			Version    string `json:"version"`
			InsertedAt string `json:"inserted_at"`
			Publisher  struct {
				Username string `json:"username"`
			} `json:"publisher"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(b, &pkgs); err != nil {
		return nil, err
	}

	var incidents []*incident.Incident
	for _, pkg := range pkgs {
		if pkg.UpdatedAt <= c.lastUpdatedAt {
			continue
		}
		if pkg.UpdatedAt > c.lastUpdatedAt {
			c.lastUpdatedAt = pkg.UpdatedAt
		}
		// Flag packages where the most recent release has a different publisher
		if len(pkg.Releases) >= 2 {
			latest := pkg.Releases[0]
			prev := pkg.Releases[1]
			if latest.Publisher.Username != prev.Publisher.Username && latest.Publisher.Username != "" {
				inc := &incident.Incident{
					ID:          fmt.Sprintf("hex-draft-%s-%s", sanitize(pkg.Name), sanitize(latest.Version)),
					Description: fmt.Sprintf("Hex package %s@%s: publisher changed from %q to %q", pkg.Name, latest.Version, prev.Publisher.Username, latest.Publisher.Username),
					AttackType:  "account_takeover",
					Severity:    "high",
					References:  []string{fmt.Sprintf("https://hex.pm/packages/%s/%s", pkg.Name, latest.Version)},
					Packages:    []incident.Package{{Name: pkg.Name, Ecosystem: "hex", AffectedVersions: []string{latest.Version}}},
				}
				log.Printf("[hex] publisher change in %s@%s", pkg.Name, latest.Version)
				incidents = append(incidents, inc)
			}
		}
	}
	return incidents, nil
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return '-'
	}, s)
}
