package cargo

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/mmcdole/gofeed"
)

const feedURL = "https://static.crates.io/feeds/new_crates.atom"

type Client struct {
	http interface {
		Do(req interface{}) (interface{}, error)
	} // not used directly
}

func New() *Client { return &Client{} }

func (c *Client) Name() string { return "cargo" }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	fp := gofeed.NewParser()
	feed, err := fp.ParseURLWithContext(feedURL, ctx)
	if err != nil {
		return nil, fmt.Errorf("cargo atom: %w", err)
	}

	var incidents []*incident.Incident
	for _, item := range feed.Items {
		if item.PublishedParsed != nil && item.PublishedParsed.Before(since) {
			continue
		}
		inc := analyseItem(item)
		if inc != nil {
			incidents = append(incidents, inc)
		}
	}
	return incidents, nil
}

// maliciousTitleKeywords are terms in crate names/descriptions that may indicate typosquatting.
var maliciousTitleKeywords = []string{
	"backdoor", "stealer", "exfil", "ransom", "cryptominer",
}

// well-known packages commonly typosquatted
var popularCrates = []string{
	"tokio", "serde", "rand", "log", "regex", "clap", "hyper",
	"reqwest", "actix", "axum", "sqlx", "diesel",
}

func analyseItem(item *gofeed.Item) *incident.Incident {
	combined := strings.ToLower(item.Title + " " + item.Description)

	// Check for explicit malicious keywords in description
	for _, kw := range maliciousTitleKeywords {
		if strings.Contains(combined, kw) {
			log.Printf("[cargo] suspicious keyword %q in: %s", kw, item.Title)
			return buildDraftIncident(item, "suspicious keyword: "+kw)
		}
	}

	// Check for typosquat attempts against popular crates
	name := extractCrateName(item.Title)
	for _, popular := range popularCrates {
		if isTyposquat(name, popular) {
			log.Printf("[cargo] possible typosquat of %q: %s", popular, name)
			return buildDraftIncident(item, fmt.Sprintf("possible typosquat of '%s'", popular))
		}
	}

	return nil
}

func buildDraftIncident(item *gofeed.Item, reason string) *incident.Incident {
	name, version := extractCrateNameVersion(item.Title)
	pkg := incident.Package{Name: name, Ecosystem: "cargo"}
	if version != "" {
		pkg.AffectedVersions = []string{version}
	}
	return &incident.Incident{
		ID:          fmt.Sprintf("cargo-draft-%s", sanitize(name)),
		Description: fmt.Sprintf("Suspicious crates.io publish: %s — %s", item.Title, reason),
		AttackType:  "typosquat",
		Severity:    "medium",
		References:  []string{item.Link},
		Packages:    []incident.Package{pkg},
	}
}

func extractCrateNameVersion(title string) (name, version string) {
	// Atom titles are typically "crate-name 0.1.0"
	parts := strings.Fields(title)
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return title, ""
}

func extractCrateName(title string) string {
	name, _ := extractCrateNameVersion(title)
	return name
}

// isTyposquat returns true when name is suspiciously close to target but not equal.
func isTyposquat(name, target string) bool {
	name = strings.ToLower(name)
	target = strings.ToLower(target)
	if name == target {
		return false
	}
	// Levenshtein distance 1 or 2 on longer names
	d := levenshtein(name, target)
	if len(target) >= 5 && d <= 2 {
		return true
	}
	if len(target) >= 3 && d == 1 {
		return true
	}
	return false
}

func levenshtein(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i, ca := range a {
		curr[0] = i + 1
		for j, cb := range b {
			if ca == cb {
				curr[j+1] = prev[j]
			} else {
				curr[j+1] = 1 + min3(prev[j], prev[j+1], curr[j])
			}
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
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
