// Package urlhaus fetches malicious URLs from abuse.ch's URLhaus public feed.
// The "recent additions" CSV (last 1000 entries) is hit on every sync.
//
// We do not fetch the full historical CSV (~3M URLs / 350 MB) — it would
// dominate the dataset, push us over GitHub size limits, and is mostly
// expired infrastructure. 1000 fresh URLs per sync gives steady-state
// coverage of active payload-hosting domains and is more useful for a
// detection feed than ancient noise.
package urlhaus

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const (
	csvURL       = "https://urlhaus.abuse.ch/downloads/csv_recent/"
	maxBodyBytes = 50 << 20
)

type Client struct {
	http *http.Client
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 60 * time.Second}}
}

func (c *Client) Name() string { return "urlhaus" }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, csvURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dragnet-bot/1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("urlhaus: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("urlhaus status %d: %s", resp.StatusCode, b)
	}

	// URLhaus prefixes the CSV with comment lines starting with '#'.
	reader := csv.NewReader(stripComments(io.LimitReader(resp.Body, maxBodyBytes)))
	reader.FieldsPerRecord = -1 // tolerate variable field counts
	reader.LazyQuotes = true

	var incidents []*incident.Incident
	rowCount := 0
	for {
		if err := ctx.Err(); err != nil {
			return incidents, err
		}
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// One bad row shouldn't kill the whole feed.
			continue
		}
		if len(row) < 7 {
			continue
		}
		rowCount++
		// CSV schema: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
		dateAdded := row[1]
		urlStr := row[2]
		urlStatus := row[3]
		threat := row[5]
		tags := row[6]

		if urlStr == "" {
			continue
		}
		if urlStatus == "offline" {
			continue // dead infrastructure adds noise without detection value
		}
		t, _ := time.Parse("2006-01-02 15:04:05", dateAdded)
		if !since.IsZero() && !t.IsZero() && t.Before(since) {
			continue
		}
		incidents = append(incidents, urlToIncident(row[0], urlStr, threat, tags, t))
	}
	log.Printf("[urlhaus] parsed %d CSV rows, kept %d active URLs", rowCount, len(incidents))
	return incidents, nil
}

func urlToIncident(id, urlStr, threat, tags string, t time.Time) *incident.Incident {
	cw := incident.CompromiseWindow{}
	if !t.IsZero() {
		cw.Start = t.UTC().Format(time.RFC3339)
	}

	host := hostFromURL(urlStr)
	inds := incident.Indicators{
		URLs: []incident.IndicatorValue{{Value: urlStr, Sources: []string{"urlhaus"}, Confidence: 0.9}},
	}
	if host != "" {
		inds.Domains = []incident.IndicatorValue{{Value: host, Sources: []string{"urlhaus"}, Confidence: 0.8}}
	}

	tagList := splitTags(tags)
	return &incident.Incident{
		ID:               "urlhaus-" + id,
		Source:           "urlhaus",
		AttackType:       "malware",
		Severity:         "high",
		Description:      fmt.Sprintf("Active malicious URL distributing %s (tags: %s)", threat, tags),
		References:       []string{"https://urlhaus.abuse.ch/url/" + id + "/"},
		CompromiseWindow: cw,
		Indicators:       inds,
		MalwareExt: &incident.MalwareExtension{
			MalwareType: threat,
			Platforms:   guessPlatforms(tagList),
		},
	}
}

func hostFromURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

func splitTags(tags string) []string {
	if tags == "" {
		return nil
	}
	parts := strings.Split(tags, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func guessPlatforms(tags []string) []string {
	for _, t := range tags {
		switch strings.ToLower(t) {
		case "elf", "mirai", "linux":
			return []string{"linux"}
		case "exe", "dll":
			return []string{"windows"}
		case "macho", "macos":
			return []string{"macos"}
		case "apk", "android":
			return []string{"android"}
		}
	}
	return nil
}

// stripComments reads from r and discards leading lines beginning with '#'.
// URLhaus pads the CSV with a multi-line schema preamble that the csv reader
// would otherwise stumble over.
func stripComments(r io.Reader) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		buf := make([]byte, 64*1024)
		var carry []byte
		inHeader := true
		for {
			n, err := r.Read(buf)
			if n > 0 {
				chunk := append(carry, buf[:n]...)
				if inHeader {
					// scan for first non-# line
					if idx := skipHeader(chunk); idx >= 0 {
						_, _ = pw.Write(chunk[idx:])
						inHeader = false
						carry = nil
					} else {
						carry = chunk
					}
				} else {
					_, _ = pw.Write(chunk)
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return pr
}

func skipHeader(b []byte) int {
	for i := 0; i < len(b); {
		// Find end of line.
		j := i
		for j < len(b) && b[j] != '\n' {
			j++
		}
		if j >= len(b) {
			return -1 // need more data
		}
		line := b[i:j]
		trim := strings.TrimSpace(string(line))
		if !strings.HasPrefix(trim, "#") && trim != "" {
			return i
		}
		i = j + 1
	}
	return -1
}
