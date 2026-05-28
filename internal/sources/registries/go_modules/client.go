package go_modules

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/httpclient"
	"github.com/dragnet-dev/dragnet/internal/incident"
)

const indexURL = "https://index.golang.org/index"

// suspiciousNamespaces are Go module path prefixes that should not have new registrations.
var suspiciousNamespaces = []string{
	"golang.org/", "google.golang.org/", "gopkg.in/go-",
}

type Client struct {
	http          *http.Client
	lastTimestamp string
}

func New() *Client                       { return &Client{http: &http.Client{Timeout: 30 * time.Second, Transport: httpclient.New()}} }
func NewWithTimestamp(ts string) *Client { c := New(); c.lastTimestamp = ts; return c }

func (c *Client) Name() string          { return "go_modules" }
func (c *Client) LastTimestamp() string { return c.lastTimestamp }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	sinceStr := since.UTC().Format(time.RFC3339)
	if c.lastTimestamp != "" {
		sinceStr = c.lastTimestamp
	}
	url := fmt.Sprintf("%s?since=%s&limit=2000", indexURL, sinceStr)
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
		return nil, fmt.Errorf("go index status %d", resp.StatusCode)
	}

	type entry struct {
		Path      string    `json:"Path"`
		Version   string    `json:"Version"`
		Timestamp time.Time `json:"Timestamp"`
	}

	var incidents []*incident.Incident
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var e entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		if e.Timestamp.After(time.Time{}) {
			c.lastTimestamp = e.Timestamp.UTC().Format(time.RFC3339Nano)
		}
		for _, ns := range suspiciousNamespaces {
			if strings.HasPrefix(e.Path, ns) {
				inc := &incident.Incident{
					ID:          fmt.Sprintf("go-draft-%s-%s", sanitize(e.Path), sanitize(e.Version)),
					Description: fmt.Sprintf("Go module claims reserved namespace: %s@%s", e.Path, e.Version),
					AttackType:  "namespace_squatting",
					Severity:    "high",
					References:  []string{fmt.Sprintf("https://pkg.go.dev/%s@%s", e.Path, e.Version)},
					Packages:    []incident.Package{{Name: e.Path, Ecosystem: "go", AffectedVersions: []string{e.Version}}},
				}
				log.Printf("[go_modules] suspicious namespace: %s@%s", e.Path, e.Version)
				incidents = append(incidents, inc)
				break
			}
		}
	}
	return incidents, scanner.Err()
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
