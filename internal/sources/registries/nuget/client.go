package nuget

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

const catalogURL = "https://api.nuget.org/v3/catalog0/index.json"

type Client struct {
	http                *http.Client
	lastCommitTimestamp string
}

func New() *Client { return &Client{http: &http.Client{Timeout: 30 * time.Second}} }

func NewWithTimestamp(ts string) *Client {
	c := New()
	c.lastCommitTimestamp = ts
	return c
}

func (c *Client) Name() string                { return "nuget" }
func (c *Client) LastCommitTimestamp() string { return c.lastCommitTimestamp }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, catalogURL, nil)
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
		return nil, fmt.Errorf("nuget catalog status %d: %s", resp.StatusCode, b)
	}
	var index struct {
		Items []struct {
			CommitTimeStamp string `json:"commitTimeStamp"`
			ID              string `json:"@id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(b, &index); err != nil {
		return nil, err
	}

	var incidents []*incident.Incident
	for _, page := range index.Items {
		if page.CommitTimeStamp <= c.lastCommitTimestamp {
			continue
		}
		incs, err := c.fetchPage(ctx, page.ID, since)
		if err != nil {
			log.Printf("[nuget] page error %s: %v", page.ID, err)
			continue
		}
		incidents = append(incidents, incs...)
		if page.CommitTimeStamp > c.lastCommitTimestamp {
			c.lastCommitTimestamp = page.CommitTimeStamp
		}
	}
	return incidents, nil
}

func (c *Client) fetchPage(ctx context.Context, pageURL string, since time.Time) ([]*incident.Incident, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var page struct {
		Items []struct {
			CatalogEntry struct {
				ID             string `json:"id"`
				Version        string `json:"version"`
				PackageEntries []struct {
					FullName string `json:"fullName"`
				} `json:"packageEntries"`
			} `json:"catalogEntry"`
			CommitTimeStamp string `json:"commitTimeStamp"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, err
	}

	var incidents []*incident.Incident
	for _, item := range page.Items {
		ts, _ := time.Parse(time.RFC3339Nano, item.CommitTimeStamp)
		if ts.Before(since) {
			continue
		}
		e := item.CatalogEntry
		// Detect MSBuild hook files (.targets / .props)
		for _, entry := range e.PackageEntries {
			name := strings.ToLower(entry.FullName)
			if strings.HasSuffix(name, ".targets") || strings.HasSuffix(name, ".props") {
				inc := &incident.Incident{
					ID:          fmt.Sprintf("nuget-draft-%s-%s", sanitize(e.ID), sanitize(e.Version)),
					Description: fmt.Sprintf("NuGet package %s@%s includes MSBuild hook file: %s", e.ID, e.Version, entry.FullName),
					AttackType:  "malicious_publish",
					Severity:    "medium",
					References:  []string{fmt.Sprintf("https://www.nuget.org/packages/%s/%s", e.ID, e.Version)},
					Packages:    []incident.Package{{Name: e.ID, Ecosystem: "nuget", AffectedVersions: []string{e.Version}}},
				}
				incidents = append(incidents, inc)
				log.Printf("[nuget] MSBuild hook in %s@%s: %s", e.ID, e.Version, entry.FullName)
				break
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
