package deps_dev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

type Client struct {
	http *http.Client
}

func New() *Client { return &Client{http: &http.Client{Timeout: 30 * time.Second}} }

func (c *Client) Name() string { return "deps_dev" }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	systems := []string{"NPM", "PYPI", "GO", "MAVEN", "CARGO"}
	var incidents []*incident.Incident
	for _, sys := range systems {
		incs, err := c.fetchSystem(ctx, sys, since)
		if err != nil {
			continue
		}
		incidents = append(incidents, incs...)
	}
	return incidents, nil
}

func (c *Client) fetchSystem(ctx context.Context, system string, since time.Time) ([]*incident.Incident, error) {
	url := fmt.Sprintf("https://api.deps.dev/v3alpha/systems/%s/advisories", system)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dragnet/1.0")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deps.dev %s status %d: %s", system, resp.StatusCode, b)
	}
	var r struct {
		Advisories []struct {
			AdvisoryKey struct {
				ID string `json:"id"`
			} `json:"advisoryKey"`
			URL      string   `json:"url"`
			Title    string   `json:"title"`
			Aliases  []string `json:"aliases"`
			Severity string   `json:"severity"`
		} `json:"advisories"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	var incidents []*incident.Incident
	for _, adv := range r.Advisories {
		inc := &incident.Incident{
			ID:          fmt.Sprintf("deps-dev-%s", sanitize(adv.AdvisoryKey.ID)),
			Description: adv.Title,
			AttackType:  "vulnerability",
			Severity:    normaliseSeverity(adv.Severity),
			References:  []string{adv.URL},
		}
		incidents = append(incidents, inc)
	}
	return incidents, nil
}

func normaliseSeverity(s string) string {
	switch s {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
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
