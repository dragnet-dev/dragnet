package maven

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

const solrURL = "https://search.maven.org/solrsearch/select"

// suspectedNamespaces are authoritative group ID prefixes that attackers may spoof.
var suspectedNamespaces = []string{
	"org.apache.", "com.google.", "org.springframework.", "com.fasterxml.",
	"io.netty.", "org.slf4j.", "commons-",
}

type Client struct {
	http          *http.Client
	lastTimestamp string
}

func New() *Client { return &Client{http: &http.Client{Timeout: 30 * time.Second}} }

func NewWithTimestamp(ts string) *Client {
	c := New()
	c.lastTimestamp = ts
	return c
}

func (c *Client) Name() string          { return "maven" }
func (c *Client) LastTimestamp() string { return c.lastTimestamp }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	// Query recent uploads sorted by timestamp descending
	url := fmt.Sprintf("%s?q=*&rows=50&wt=json&core=gav&sort=timestamp+desc", solrURL)
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
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("maven solr status %d: %s", resp.StatusCode, b)
	}

	var r struct {
		Response struct {
			Docs []struct {
				ID         string `json:"id"`
				GroupID    string `json:"g"`
				ArtifactID string `json:"a"`
				Version    string `json:"v"`
				Timestamp  int64  `json:"timestamp"`
			} `json:"docs"`
		} `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}

	var incidents []*incident.Incident
	for _, doc := range r.Response.Docs {
		ts := time.UnixMilli(doc.Timestamp)
		if ts.Before(since) {
			continue
		}
		inc := analyseDoc(doc.GroupID, doc.ArtifactID, doc.Version)
		if inc != nil {
			log.Printf("[maven] anomaly in %s:%s:%s", doc.GroupID, doc.ArtifactID, doc.Version)
			incidents = append(incidents, inc)
		}
	}
	return incidents, nil
}

func analyseDoc(groupID, artifactID, version string) *incident.Incident {
	// Detect namespace squatting — popular group IDs from non-standard publishers
	for _, ns := range suspectedNamespaces {
		if strings.HasPrefix(groupID, ns) {
			// Heuristic: if the artifact has an unusual name or version pattern, flag it
			if strings.ContainsAny(artifactID, "0123456789") && len(version) < 3 {
				coord := fmt.Sprintf("%s:%s:%s", groupID, artifactID, version)
				return &incident.Incident{
					ID:          fmt.Sprintf("maven-draft-%s", sanitize(coord)),
					Description: fmt.Sprintf("Suspicious Maven Central publish: %s — potential namespace squatting of %s", coord, ns),
					AttackType:  "namespace_squatting",
					Severity:    "medium",
					References:  []string{fmt.Sprintf("https://search.maven.org/artifact/%s/%s/%s/jar", groupID, artifactID, version)},
					Packages:    []incident.Package{{Name: groupID + ":" + artifactID, Ecosystem: "maven", AffectedVersions: []string{version}}},
				}
			}
		}
	}
	return nil
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
