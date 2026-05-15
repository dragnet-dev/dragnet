package blogs

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/dragnet-dev/dragnet/internal/confidence"
	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/mmcdole/gofeed"
)

// maxHTMLBytes caps each fetched HTML body. 5 MiB is plenty for any blog post
// and prevents OOM if a malicious source returns an unbounded stream.
const maxHTMLBytes = 5 << 20

// Client wraps a BlogParser and implements sources.Source.
type Client struct {
	parser BlogParser
	http   *http.Client
}

// sharedHTTPClient is SSRF-safe: its Dialer rejects connections to private,
// loopback, and link-local IPs. Blog feeds publish arbitrary URLs that this
// client follows, so untrusted upstream feeds must not be able to point us at
// internal services.
var sharedHTTPClient = newSafeHTTPClient(30 * time.Second)

func NewClient(parser BlogParser) *Client {
	return &Client{
		parser: parser,
		http:   sharedHTTPClient,
	}
}

func (c *Client) Name() string { return c.parser.Name() }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	fp := gofeed.NewParser()
	feed, err := fp.ParseURLWithContext(c.parser.FeedURL(), ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch rss %s: %w", c.parser.FeedURL(), err)
	}

	var incidents []*incident.Incident
	for _, item := range feed.Items {
		if item.PublishedParsed != nil && item.PublishedParsed.Before(since) {
			continue
		}
		desc := ""
		if item.Description != "" {
			desc = item.Description
		}
		if !c.parser.MatchesPost(item.Title, desc) {
			continue
		}

		html, err := c.fetchHTML(ctx, item.Link)
		if err != nil {
			log.Printf("[%s] fetch html %s: %v", c.parser.Name(), item.Link, err)
			continue
		}

		iocs, pkgs, err := c.parser.ParseIOCs(html)
		if err != nil {
			log.Printf("[%s] parse iocs %s: %v", c.parser.Name(), item.Link, err)
			continue
		}
		// Supplement parser-returned packages with generic extraction so that
		// merging on packageOverlap works even when parsers don't detect them.
		pkgs = mergePackages(pkgs, ExtractPackages(html))
		if len(iocs) == 0 && len(pkgs) == 0 {
			continue
		}

		inc := iocsToDraftIncident(c.parser.Name(), item.Link, item.Title, item.PublishedParsed, iocs, pkgs)
		incidents = append(incidents, inc)
	}
	return incidents, nil
}

func (c *Client) fetchHTML(ctx context.Context, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", fmt.Errorf("new request %s: %w", rawURL, err)
	}
	req.Header.Set("User-Agent", "Dragnet-CTI-Bot/1.0 (+https://github.com/dragnet-dev/dragnet)")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("http %d: %s", resp.StatusCode, rawURL)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTMLBytes))
	if err != nil {
		return "", fmt.Errorf("read body %s: %w", rawURL, err)
	}
	return string(body), nil
}

// newSafeHTTPClient returns an http.Client whose Dialer rejects connections
// to private, loopback, and link-local addresses. Suitable for fetchers that
// follow URLs from untrusted upstream sources (RSS feeds, blog posts).
func newSafeHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: ssrfSafeControl,
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// ssrfSafeControl rejects connections whose resolved address is private,
// loopback, link-local, or unspecified. The address parameter is "ip:port"
// after DNS resolution.
func ssrfSafeControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrf: split host: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("ssrf: %q is not an IP", host)
	}
	if isBlockedIP(ip) {
		return fmt.Errorf("ssrf: blocked address %s", host)
	}
	return nil
}

func isBlockedIP(ip net.IP) bool {
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsUnspecified()
}

// blogIncidentID derives a stable human-readable ID from the source, article title,
// and a 4-byte hash of the URL for uniqueness.
func blogIncidentID(source, ref, title string) string {
	h := sha256.Sum256([]byte(ref))
	hashSuffix := fmt.Sprintf("%x", h[:4])
	slug := slugifyTitle(title)
	if slug == "" {
		return source + "-" + hashSuffix
	}
	return source + "-" + slug + "-" + hashSuffix
}

// slugifyTitle converts a free-form title into a URL-safe slug of at most 40 chars.
func slugifyTitle(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	prevDash := true
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash {
			b.WriteRune('-')
			prevDash = true
		}
	}
	result := strings.TrimRight(b.String(), "-")
	if len(result) > 40 {
		result = strings.TrimRight(result[:40], "-")
	}
	return result
}

// mergePackages returns a deduped union of two AffectedPackage slices.
// primary takes precedence; generic are appended only when not already seen.
func mergePackages(primary, generic []AffectedPackage) []AffectedPackage {
	seen := map[string]bool{}
	out := make([]AffectedPackage, 0, len(primary)+len(generic))
	for _, p := range primary {
		key := strings.ToLower(p.Ecosystem + "|" + p.Name)
		if !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	for _, p := range generic {
		key := strings.ToLower(p.Ecosystem + "|" + p.Name)
		if !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}

func iocsToDraftIncident(source, ref, title string, pubTime *time.Time, iocs []RawIOC, pkgs []AffectedPackage) *incident.Incident {
	inc := &incident.Incident{
		ID:         blogIncidentID(source, ref, title),
		Source:     source,
		References: []string{ref},
	}
	if pubTime != nil && !pubTime.IsZero() {
		inc.CompromiseWindow.Start = pubTime.Format(time.RFC3339)
	}
	inc.Packages = make([]incident.Package, 0, len(pkgs))
	for _, pkg := range pkgs {
		inc.Packages = append(inc.Packages, incident.Package{
			Name:      pkg.Name,
			Ecosystem: pkg.Ecosystem,
		})
	}
	conf := confidence.Calculate([]string{source})
	for _, ioc := range iocs {
		switch ioc.Type {
		case "domain":
			inc.Indicators.Domains = append(inc.Indicators.Domains, incident.IndicatorValue{
				Value: ioc.Value, Sources: []string{ioc.Source}, Confidence: conf,
			})
		case "ip":
			inc.Indicators.IPs = append(inc.Indicators.IPs, incident.IndicatorValue{
				Value: ioc.Value, Sources: []string{ioc.Source}, Confidence: conf,
			})
		case "url":
			inc.Indicators.URLs = append(inc.Indicators.URLs, incident.IndicatorValue{
				Value: ioc.Value, Sources: []string{ioc.Source}, Confidence: conf,
			})
		case "sha256", "sha1", "md5":
			inc.Indicators.FileHashes = append(inc.Indicators.FileHashes, incident.FileHash{
				Algorithm:  ioc.Type,
				Value:      ioc.Value,
				Filename:   ioc.Filename,
				Sources:    []string{ioc.Source},
				Confidence: conf,
			})
		case "file_name":
			inc.Indicators.FileNames = append(inc.Indicators.FileNames, ioc.Value)
		}
	}
	return inc
}
