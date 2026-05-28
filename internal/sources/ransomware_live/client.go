// Package ransomware_live fetches ransomware victim claims from
// ransomware.live's public JSON API.
//
// Previously this source only hit /recentvictims, which caps at 100 records.
// On first sync we now walk month-by-month from January 2020 through the
// current month using /victims/{year}/{month} so the full historical corpus
// (~30,000 claims) lands in haul. Incremental syncs only hit /recentvictims
// because year-month iteration would be wasted bandwidth when nothing
// further back has changed.
package ransomware_live

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

const (
	recentURL    = "https://api.ransomware.live/v1/recentvictims"
	monthlyURL   = "https://api.ransomware.live/v1/victims/%d/%d" // year, month
	maxBodyBytes = 100 << 20
	historyStart = 2020
	// Switch between recent-only and full backfill: incremental syncs (since
	// less than 30 days ago) just hit /recentvictims; first runs hit every month.
	recentCutoff = 30 * 24 * time.Hour
)

type Client struct {
	http *http.Client
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) Name() string { return "ransomware_live" }

// victim mirrors the ransomware.live v1 API shape. Note the field naming —
// the v1 schema uses post_title for the victim's name (not victim_name) and
// post_url for the leak-site URL. The v0 schema we originally coded against
// either redirected or returned different fields silently — the resulting
// 28k-victim-fetch-with-0-kept silent failure was caught during validation.
type victim struct {
	Group       string `json:"group_name"`
	Victim      string `json:"post_title"`
	Country     string `json:"country"`
	Description string `json:"description"`
	Published   string `json:"published"`
	Discovered  string `json:"discovered"`
	URL         string `json:"post_url"`
	Activity    string `json:"activity"`
}

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	if !since.IsZero() && time.Since(since) <= recentCutoff {
		return c.fetchRecent(ctx, since)
	}
	return c.fetchHistorical(ctx, since)
}

func (c *Client) fetchRecent(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	victims, err := c.getVictims(ctx, recentURL)
	if err != nil {
		return nil, err
	}
	log.Printf("[ransomware_live] recent feed: %d victims", len(victims))
	return victimsToIncidents(victims, since), nil
}

func (c *Client) fetchHistorical(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	now := time.Now().UTC()
	startYear := historyStart
	if !since.IsZero() && since.Year() > startYear {
		startYear = since.Year()
	}

	var all []victim
	for y := startYear; y <= now.Year(); y++ {
		monthStart := 1
		monthEnd := 12
		if y == now.Year() {
			monthEnd = int(now.Month())
		}
		if y == startYear && !since.IsZero() && y == since.Year() {
			monthStart = int(since.Month())
		}
		for m := monthStart; m <= monthEnd; m++ {
			if err := ctx.Err(); err != nil {
				log.Printf("[ransomware_live] historical fetch cancelled at %d-%02d (have %d)", y, m, len(all))
				return victimsToIncidents(all, since), nil
			}
			url := fmt.Sprintf(monthlyURL, y, m)
			victims, err := c.getVictims(ctx, url)
			if err != nil {
				log.Printf("[ransomware_live] %d-%02d: %v (continuing)", y, m, err)
				continue
			}
			all = append(all, victims...)
		}
	}
	log.Printf("[ransomware_live] historical (%d..%d): %d victims", startYear, now.Year(), len(all))
	return victimsToIncidents(all, since), nil
}

func (c *Client) getVictims(ctx context.Context, url string) ([]victim, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dragnet-bot/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ransomware.live: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // month may not exist (e.g., future month)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ransomware.live status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	var victims []victim
	if err := json.Unmarshal(body, &victims); err != nil {
		return nil, fmt.Errorf("ransomware.live decode: %w", err)
	}
	return victims, nil
}

func victimsToIncidents(victims []victim, since time.Time) []*incident.Incident {
	out := make([]*incident.Incident, 0, len(victims))
	seen := map[string]bool{}
	for _, v := range victims {
		if v.Victim == "" {
			continue
		}
		// v1 published format is RFC3339 with microseconds (e.g.
		// "2025-01-31T18:51:48.605194+00:00"); fall back to the legacy
		// space-separated format if that parse fails.
		var t time.Time
		dateStr := v.Published
		if dateStr == "" {
			dateStr = v.Discovered
		}
		if dateStr != "" {
			t, _ = time.Parse(time.RFC3339Nano, dateStr)
			if t.IsZero() {
				t, _ = time.Parse("2006-01-02 15:04:05.999999", dateStr)
			}
			if t.IsZero() {
				t, _ = time.Parse("2006-01-02 15:04:05", dateStr)
			}
			if !since.IsZero() && !t.IsZero() && t.Before(since) {
				continue
			}
		}
		id := "ransomware_live-" + slugify(v.Group) + "-" + slugify(v.Victim)
		if !t.IsZero() {
			id += "-" + t.Format("20060102")
		}
		if seen[id] {
			continue
		}
		seen[id] = true

		cw := incident.CompromiseWindow{}
		if !t.IsZero() {
			cw.Start = t.UTC().Format(time.RFC3339)
		}

		inc := &incident.Incident{
			ID:               id,
			Source:           "ransomware_live",
			AttackType:       "ransomware",
			Severity:         "high",
			Description:      describeVictim(v),
			CompromiseWindow: cw,
			RansomwareExt: &incident.RansomwareExtension{
				RansomwareGroup:   v.Group,
				TargetedCountries: countryList(v.Country),
				TargetedSectors:   sectorList(v.Activity),
			},
		}
		if v.URL != "" {
			// ransomware.live API occasionally emits single-slash URLs
			// (e.g. "http:/host.onion/...") — fix before storing.
			rawURL := fixSingleSlash(v.URL)
			if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
				inc.References = []string{rawURL}
				// Also surface the leak-site URL as a URL indicator so it flows
				// into feeds/unified.{json,jsonl} and SOAR pipelines that watch
				// for ransomware infrastructure.
				inc.Indicators.URLs = append(inc.Indicators.URLs, incident.IndicatorValue{
					Value:      rawURL,
					Sources:    []string{"ransomware_live"},
					Confidence: 0.9,
				})
			}
		}
		out = append(out, inc)
	}
	return out
}

func describeVictim(v victim) string {
	parts := []string{fmt.Sprintf("Ransomware victim claim by %s: %s", flattenWS(v.Group), flattenWS(v.Victim))}
	if v.Country != "" {
		parts = append(parts, "country: "+flattenWS(v.Country))
	}
	if v.Activity != "" {
		parts = append(parts, "sector: "+flattenWS(v.Activity))
	}
	return strings.Join(parts, "; ")
}

// flattenWS collapses any internal whitespace and repairs double-encoded UTF-8
// sequences. ransomware.live occasionally stores victim names whose UTF-8 bytes
// were decoded as Latin-1 (e.g. U+2019 → â\x80\x99). We reverse that by
// re-encoding as Latin-1 and decoding as UTF-8; any C1 control characters that
// survive are stripped. Both conditions break YAML parsing in downstream backends.
func flattenWS(s string) string {
	s = fixMojibake(s)
	return strings.Join(strings.Fields(s), " ")
}

// fixMojibake attempts to reverse UTF-8-bytes-as-Latin-1 double-encoding, then
// strips any remaining C1 control characters (U+0080–U+009F).
func fixMojibake(s string) string {
	// Attempt full reversal: encode as Latin-1, decode as UTF-8.
	if b, err := encodeAsLatin1(s); err == nil {
		if fixed, err := decodeAsUTF8(b); err == nil {
			s = fixed
		}
	}
	// Strip any remaining C1 control characters.
	var out strings.Builder
	for _, r := range s {
		if r < 0x80 || r > 0x9F {
			out.WriteRune(r)
		}
	}
	return out.String()
}

func encodeAsLatin1(s string) ([]byte, error) {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0xFF {
			return nil, fmt.Errorf("rune out of Latin-1 range: %U", r)
		}
		b = append(b, byte(r))
	}
	return b, nil
}

func decodeAsUTF8(b []byte) (string, error) {
	s := string(b)
	for _, r := range s {
		if r == '�' {
			return "", fmt.Errorf("invalid UTF-8")
		}
	}
	return s, nil
}

func slugify(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			out = append(out, c)
		case c >= '0' && c <= '9':
			out = append(out, c)
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
		default:
			if len(out) > 0 && out[len(out)-1] != '-' {
				out = append(out, '-')
			}
		}
	}
	for len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	return string(out)
}

func countryList(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func sectorList(s string) []string {
	s = flattenWS(s)
	if s == "" {
		return nil
	}
	// ransomware.live sometimes returns comma-separated sectors ("Healthcare, Finance").
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// fixSingleSlash corrects "http:/host" → "http://host" from the
// ransomware.live API which occasionally omits the second slash.
func fixSingleSlash(u string) string {
	if strings.HasPrefix(u, "http:/") && !strings.HasPrefix(u, "http://") {
		return "http://" + u[6:]
	}
	if strings.HasPrefix(u, "https:/") && !strings.HasPrefix(u, "https://") {
		return "https://" + u[7:]
	}
	return u
}
