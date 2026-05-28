package pub

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
	http        *http.Client
	lastUpdated string
}

func New() *Client                     { return &Client{http: &http.Client{Timeout: 30 * time.Second, Transport: httpclient.New()}} }
func NewWithUpdated(ts string) *Client { c := New(); c.lastUpdated = ts; return c }

func (c *Client) Name() string        { return "pub" }
func (c *Client) LastUpdated() string { return c.lastUpdated }

func (c *Client) Fetch(ctx context.Context, _ time.Time) ([]*incident.Incident, error) {
	url := "https://pub.dev/api/packages?ordering=updated"
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
		return nil, fmt.Errorf("pub.dev status %d: %s", resp.StatusCode, b)
	}

	var r struct {
		Packages []struct {
			Name           string `json:"name"`
			Updated        string `json:"updated"`
			LatestVersion  string `json:"latestVersion"`
			PublisherEmail string `json:"publisherEmail"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}

	var incidents []*incident.Incident
	for _, pkg := range r.Packages {
		if pkg.Updated <= c.lastUpdated {
			continue
		}
		if pkg.Updated > c.lastUpdated {
			c.lastUpdated = pkg.Updated
		}
		// Flag packages with unusual publisher emails (non-standard TLDs)
		if isUnusualPublisher(pkg.PublisherEmail) {
			inc := &incident.Incident{
				ID:          fmt.Sprintf("pub-draft-%s-%s", sanitize(pkg.Name), sanitize(pkg.LatestVersion)),
				Description: fmt.Sprintf("pub.dev package %s@%s has unusual publisher: %s", pkg.Name, pkg.LatestVersion, pkg.PublisherEmail),
				AttackType:  "malicious_publish",
				Severity:    "low",
				References:  []string{fmt.Sprintf("https://pub.dev/packages/%s", pkg.Name)},
				Packages:    []incident.Package{{Name: pkg.Name, Ecosystem: "pub", AffectedVersions: []string{pkg.LatestVersion}}},
			}
			log.Printf("[pub] unusual publisher for %s@%s: %s", pkg.Name, pkg.LatestVersion, pkg.PublisherEmail)
			incidents = append(incidents, inc)
		}
	}
	return incidents, nil
}

func isUnusualPublisher(email string) bool {
	if email == "" {
		return false
	}
	// Flag non-standard TLDs that may indicate disposable email addresses
	unusual := []string{".xyz", ".top", ".click", ".online", ".site", ".space"}
	lower := strings.ToLower(email)
	for _, tld := range unusual {
		if strings.HasSuffix(lower, tld) {
			return true
		}
	}
	return false
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
