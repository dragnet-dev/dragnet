package packagist

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/mmcdole/gofeed"
)

const feedURL = "https://packagist.org/feeds/releases.rss"

type Client struct {
	lastETag    string
	lastPubDate string
}

func New() *Client                    { return &Client{} }
func NewWithETag(etag string) *Client { return &Client{lastETag: etag} }

func (c *Client) Name() string     { return "packagist" }
func (c *Client) LastETag() string { return c.lastETag }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	fp := gofeed.NewParser()
	feed, err := fp.ParseURLWithContext(feedURL, ctx)
	if err != nil {
		return nil, err
	}

	var incidents []*incident.Incident
	for _, item := range feed.Items {
		if item.PublishedParsed != nil && item.PublishedParsed.Before(since) {
			continue
		}
		if hasHook(item.Description) {
			log.Printf("[packagist] composer hook detected: %s", item.Title)
			name, version := parseTitle(item.Title)
			inc := &incident.Incident{
				ID:          fmt.Sprintf("packagist-draft-%s-%s", sanitize(name), sanitize(version)),
				Description: fmt.Sprintf("Packagist package %s includes composer lifecycle hook", item.Title),
				AttackType:  "malicious_publish",
				Severity:    "medium",
				References:  []string{item.Link},
				Packages:    []incident.Package{{Name: name, Ecosystem: "packagist", AffectedVersions: []string{version}}},
			}
			incidents = append(incidents, inc)
		}
	}
	return incidents, nil
}

func hasHook(description string) bool {
	hooks := []string{"pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd", "post-root-package-install"}
	lower := strings.ToLower(description)
	for _, h := range hooks {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}

func parseTitle(title string) (name, version string) {
	parts := strings.Fields(title)
	if len(parts) >= 2 {
		return parts[0], parts[len(parts)-1]
	}
	return title, ""
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
