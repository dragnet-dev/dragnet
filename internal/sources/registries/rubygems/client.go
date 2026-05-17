package rubygems

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

type Client struct {
	http          *http.Client
	lastTimestamp string
}

func New() *Client                       { return &Client{http: &http.Client{Timeout: 30 * time.Second}} }
func NewWithTimestamp(ts string) *Client { c := New(); c.lastTimestamp = ts; return c }

func (c *Client) Name() string          { return "rubygems" }
func (c *Client) LastTimestamp() string { return c.lastTimestamp }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	// RubyGems' timeframe_versions endpoint caps the window at 7 days. Clamp
	// `from` to (now - 7d) so first-run / long-gap syncs don't 400 with
	// "the supplied query time range cannot exceed 7 days". OSV bulk already
	// covers historical RubyGems advisories — this source's value is the
	// real-time "new gem with executables" signal in the most recent week.
	now := time.Now().UTC()
	earliest := now.Add(-7 * 24 * time.Hour)
	if since.IsZero() || since.Before(earliest) {
		since = earliest
	}
	from := since.Format(time.RFC3339)
	to := now.Format(time.RFC3339)
	url := fmt.Sprintf("https://rubygems.org/api/v1/timeframe_versions.json?from=%s&to=%s", from, to)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rubygems status %d: %s", resp.StatusCode, b)
	}
	var gems []struct {
		Name        string   `json:"name"`
		Number      string   `json:"number"`
		GemURI      string   `json:"gem_uri"`
		Executables []string `json:"executables"`
	}
	if err := json.Unmarshal(b, &gems); err != nil {
		return nil, err
	}
	var incidents []*incident.Incident
	for _, g := range gems {
		if len(g.Executables) > 0 {
			inc := &incident.Incident{
				ID:          fmt.Sprintf("rubygems-draft-%s-%s", sanitize(g.Name), sanitize(g.Number)),
				Description: fmt.Sprintf("RubyGems %s@%s adds executables: %s", g.Name, g.Number, strings.Join(g.Executables, ", ")),
				AttackType:  "malicious_publish",
				Severity:    "medium",
				References:  []string{g.GemURI},
				Packages:    []incident.Package{{Name: g.Name, Ecosystem: "rubygems", AffectedVersions: []string{g.Number}}},
			}
			log.Printf("[rubygems] executables in %s@%s: %v", g.Name, g.Number, g.Executables)
			incidents = append(incidents, inc)
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
