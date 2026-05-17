// Package nvd fetches CVE records from the NVD REST API v2.0.
//
// NVD enforces two constraints we have to respect:
//   - A single request may cover at most 120 days of pubStartDate→pubEndDate.
//   - Results are paginated; resultsPerPage maxes out at 2000.
//
// On first sync (`since` = epoch) we walk backwards in 119-day windows.
// With an NVD_API_KEY env var set, we cover the last 2 years (~60k high/
// critical CVEs after filtering) at the keyed rate limit (50 req / 30 s).
// Without a key, NVD enforces 5 req / 30 s — we'd burn the per-source
// timeout long before covering 2 years, so we shorten to 1 year and pause
// 7 s between requests. The first window after `since` still completes
// even when rate-limited; subsequent ones return partial data with a
// logged 429.
//
// We keep only CVEs whose CVSS v3 base score is unknown or ≥ 7.0 — the
// low/medium tier is enormous noise for an intel feed and OSV/GHSA already
// cover the package-relevant subset.
package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const (
	apiURL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	windowDays    = 119      // NVD limit is 120; stay just inside
	resultsPerPg  = 2000     // NVD max
	bodyReadLimit = 200 << 20 // 200 MiB per response
	minCVSSKept   = 7.0      // drop low/medium CVEs
)

// Backfill and pause depend on whether an API key is available.
//
//   - With key: 50 req / 30s allowed → 1 s pause, 2 yr backfill.
//   - Without:  5 req / 30s allowed → 7 s pause, 1 yr backfill (otherwise
//     we'd burn the per-source timeout and lose all data).
var (
	maxBackfillKeyed   = 2 * 365 * 24 * time.Hour
	maxBackfillUnkeyed = 1 * 365 * 24 * time.Hour
	requestPauseKeyed   = 1 * time.Second
	requestPauseUnkeyed = 7 * time.Second
)

type Client struct {
	http   *http.Client
	apiKey string
}

func New() *Client {
	return &Client{
		http:   &http.Client{Timeout: 60 * time.Second},
		apiKey: os.Getenv("NVD_API_KEY"),
	}
}

func (c *Client) Name() string { return "nvd" }

func (c *Client) backfill() time.Duration {
	if c.apiKey != "" {
		return maxBackfillKeyed
	}
	return maxBackfillUnkeyed
}

func (c *Client) pause() time.Duration {
	if c.apiKey != "" {
		return requestPauseKeyed
	}
	return requestPauseUnkeyed
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CVSSV31 []struct {
			CVSSData struct {
				BaseScore    float64 `json:"baseScore"`
				VectorString string  `json:"vectorString"`
			} `json:"cvssData"`
		} `json:"cvssMetricV31"`
		CVSSV30 []struct {
			CVSSData struct {
				BaseScore    float64 `json:"baseScore"`
				VectorString string  `json:"vectorString"`
			} `json:"cvssData"`
		} `json:"cvssMetricV30"`
	} `json:"metrics"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type nvdResponse struct {
	ResultsPerPage  int       `json:"resultsPerPage"`
	StartIndex      int       `json:"startIndex"`
	TotalResults    int       `json:"totalResults"`
	Vulnerabilities []struct{ CVE nvdCVE `json:"cve"` } `json:"vulnerabilities"`
}

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	end := time.Now().UTC()
	start := since.UTC()
	bf := c.backfill()
	if start.IsZero() || end.Sub(start) > bf {
		start = end.Add(-bf)
	}

	keyMode := "unkeyed"
	if c.apiKey != "" {
		keyMode = "keyed"
	}
	log.Printf("[nvd] fetching CVEs from %s to %s (%d days, %s, pause=%s)", start.Format("2006-01-02"), end.Format("2006-01-02"), int(end.Sub(start).Hours()/24), keyMode, c.pause())

	var all []*incident.Incident
	windowStart := start
	for windowStart.Before(end) {
		if err := ctx.Err(); err != nil {
			// Return what we have so far as a *successful* partial result.
			// The per-source timeout is the most common reason we land here;
			// discarding 17k useful CVEs because we couldn't fetch the next
			// 5k makes for terrible data freshness.
			log.Printf("[nvd] %s after %d records — returning partial (windowStart=%s)",
				err, len(all), windowStart.Format("2006-01-02"))
			return all, nil
		}
		windowEnd := windowStart.Add(windowDays * 24 * time.Hour)
		if windowEnd.After(end) {
			windowEnd = end
		}

		recs, err := c.fetchWindow(ctx, windowStart, windowEnd)
		// Always append the partial recs from this window so context-deadline
		// mid-window doesn't lose them.
		all = append(all, recs...)
		if err != nil {
			log.Printf("[nvd] window %s..%s: %v (kept %d so far, continuing)",
				windowStart.Format("2006-01-02"), windowEnd.Format("2006-01-02"), err, len(all))
		} else {
			log.Printf("[nvd] window %s..%s: %d kept (total %d)",
				windowStart.Format("2006-01-02"), windowEnd.Format("2006-01-02"), len(recs), len(all))
		}
		windowStart = windowEnd
	}
	return all, nil
}

func (c *Client) fetchWindow(ctx context.Context, start, end time.Time) ([]*incident.Incident, error) {
	var out []*incident.Incident
	startIdx := 0
	for {
		if err := ctx.Err(); err != nil {
			// Return partial; caller appends what we have.
			return out, err
		}
		page, err := c.fetchPage(ctx, start, end, startIdx)
		// Always retain any successfully-decoded entries even if a later
		// page errors out (rate limit, timeout, etc).
		out = append(out, page.kept...)
		if err != nil {
			return out, err
		}
		if page.next >= page.total || page.next == startIdx {
			return out, nil
		}
		startIdx = page.next
		select {
		case <-time.After(c.pause()):
		case <-ctx.Done():
			return out, ctx.Err()
		}
	}
}

type pageResult struct {
	kept  []*incident.Incident
	next  int
	total int
}

func (c *Client) fetchPage(ctx context.Context, start, end time.Time, startIdx int) (pageResult, error) {
	params := url.Values{}
	params.Set("pubStartDate", start.Format("2006-01-02T15:04:05.000"))
	params.Set("pubEndDate", end.Format("2006-01-02T15:04:05.000"))
	params.Set("resultsPerPage", fmt.Sprintf("%d", resultsPerPg))
	params.Set("startIndex", fmt.Sprintf("%d", startIdx))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"?"+params.Encode(), nil)
	if err != nil {
		return pageResult{}, err
	}
	req.Header.Set("User-Agent", "dragnet-bot/1.0")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return pageResult{}, fmt.Errorf("nvd request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		// Caller treats this as a soft fail and returns what we have so far.
		return pageResult{next: 0, total: 0}, fmt.Errorf("nvd rate limited (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return pageResult{}, fmt.Errorf("nvd status %d: %s", resp.StatusCode, b)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, bodyReadLimit))
	if err != nil {
		return pageResult{}, err
	}
	var data nvdResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return pageResult{}, fmt.Errorf("nvd decode: %w", err)
	}

	res := pageResult{
		next:  data.StartIndex + len(data.Vulnerabilities),
		total: data.TotalResults,
	}
	for _, v := range data.Vulnerabilities {
		if inc := toIncident(v.CVE); inc != nil {
			res.kept = append(res.kept, inc)
		}
	}
	return res, nil
}

func toIncident(cve nvdCVE) *incident.Incident {
	desc := ""
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}
	if strings.HasPrefix(desc, "** REJECT **") || strings.HasPrefix(desc, "** DISPUTED **") {
		return nil
	}

	var score float64
	var vector string
	switch {
	case len(cve.Metrics.CVSSV31) > 0:
		score = cve.Metrics.CVSSV31[0].CVSSData.BaseScore
		vector = cve.Metrics.CVSSV31[0].CVSSData.VectorString
	case len(cve.Metrics.CVSSV30) > 0:
		score = cve.Metrics.CVSSV30[0].CVSSData.BaseScore
		vector = cve.Metrics.CVSSV30[0].CVSSData.VectorString
	}
	if score > 0 && score < minCVSSKept {
		return nil
	}

	refs := make([]string, 0, len(cve.References))
	for _, r := range cve.References {
		refs = append(refs, r.URL)
	}

	cw := incident.CompromiseWindow{}
	if t, err := time.Parse(time.RFC3339, cve.Published); err == nil {
		cw.Start = t.UTC().Format(time.RFC3339)
	}

	return &incident.Incident{
		ID:               "nvd-" + cve.ID,
		Source:           "nvd",
		AttackType:       "vulnerability",
		Severity:         cvssToSeverity(score),
		Description:      desc,
		References:       refs,
		CompromiseWindow: cw,
		CVEExt: &incident.CVEExtension{
			CVEID:      cve.ID,
			CVSSScore:  score,
			CVSSVector: vector,
		},
	}
}

func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}
