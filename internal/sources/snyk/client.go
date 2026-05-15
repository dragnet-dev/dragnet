package snyk

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

func (c *Client) Name() string { return "snyk" }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	ecosystems := []string{"npm", "pypi", "maven", "nuget", "rubygems", "golang"}
	var incidents []*incident.Incident
	for _, eco := range ecosystems {
		incs, err := c.fetchEcosystem(ctx, eco, since)
		if err != nil {
			continue
		}
		incidents = append(incidents, incs...)
	}
	return incidents, nil
}

func (c *Client) fetchEcosystem(ctx context.Context, ecosystem string, since time.Time) ([]*incident.Incident, error) {
	url := fmt.Sprintf("https://security.snyk.io/api/v1/vulns?type=%s&sortBy=disclosureTime&order=desc", ecosystem)
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
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("snyk %s status %d", ecosystem, resp.StatusCode)
	}
	var r struct {
		Vulnerabilities []struct {
			ID          string    `json:"id"`
			Title       string    `json:"title"`
			PackageName string    `json:"packageName"`
			Version     string    `json:"version"`
			Severity    string    `json:"severity"`
			PublishedAt time.Time `json:"publicationTime"`
			References  []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	var incidents []*incident.Incident
	for _, v := range r.Vulnerabilities {
		if v.PublishedAt.Before(since) {
			continue
		}
		var refs []string
		for _, ref := range v.References {
			if ref.URL != "" {
				refs = append(refs, ref.URL)
			}
		}
		inc := &incident.Incident{
			ID:          fmt.Sprintf("snyk-%s", sanitize(v.ID)),
			Description: v.Title,
			AttackType:  "vulnerability",
			Severity:    normaliseSeverity(v.Severity),
			References:  refs,
			Packages:    []incident.Package{{Name: v.PackageName, Ecosystem: normaliseEcosystem(ecosystem), AffectedVersions: []string{v.Version}}},
		}
		incidents = append(incidents, inc)
	}
	return incidents, nil
}

func normaliseSeverity(s string) string {
	switch s {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

func normaliseEcosystem(s string) string {
	if s == "golang" {
		return "go"
	}
	return s
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
