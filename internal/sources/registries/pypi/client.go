package pypi

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/httpclient"
	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/mmcdole/gofeed"
)

const feedURL = "https://pypi.org/rss/updates.xml"

// keywords that suggest a malicious package description
var suspiciousKeywords = []string{
	"reverse shell", "backdoor", "exfil", "stealer", "credential harvest",
	"cryptominer", "keylogger", "ransomware",
}

type Client struct {
	http     *http.Client
	lastETag string
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 30 * time.Second, Transport: httpclient.New()}}
}

func NewWithETag(etag string) *Client {
	c := New()
	c.lastETag = etag
	return c
}

func (c *Client) Name() string { return "pypi" }

func (c *Client) LastETag() string { return c.lastETag }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	if c.lastETag != "" {
		req.Header.Set("If-None-Match", c.lastETag)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("pypi rss status %d: %s", resp.StatusCode, b)
	}

	if etag := resp.Header.Get("ETag"); etag != "" {
		c.lastETag = etag
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	fp := gofeed.NewParser()
	feed, err := fp.ParseString(string(body))
	if err != nil {
		return nil, err
	}

	var incidents []*incident.Incident
	for _, item := range feed.Items {
		if item.PublishedParsed != nil && item.PublishedParsed.Before(since) {
			continue
		}

		inc := c.analyseItem(item)
		if inc != nil {
			incidents = append(incidents, inc)
		}
	}
	return incidents, nil
}

func (c *Client) analyseItem(item *gofeed.Item) *incident.Incident {
	combined := strings.ToLower(item.Title + " " + item.Description)
	var found []string
	for _, kw := range suspiciousKeywords {
		if strings.Contains(combined, kw) {
			found = append(found, kw)
		}
	}
	if len(found) == 0 {
		return nil
	}

	log.Printf("[pypi] suspicious keywords in %s: %s", item.Title, strings.Join(found, ", "))

	name, version := parsePackageTitle(item.Title)
	return &incident.Incident{
		ID:          fmt.Sprintf("pypi-draft-%s-%s", sanitize(name), sanitize(version)),
		Description: fmt.Sprintf("Suspicious PyPI publish: %s — keywords: %s", item.Title, strings.Join(found, ", ")),
		AttackType:  "malicious_publish",
		Severity:    "medium",
		References:  []string{item.Link},
		Packages: []incident.Package{
			{Name: name, Ecosystem: "pypi", AffectedVersions: []string{version}},
		},
	}
}

// parsePackageTitle parses "package 1.0.0" style PyPI RSS titles.
func parsePackageTitle(title string) (name, version string) {
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
