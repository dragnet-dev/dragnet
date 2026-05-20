package blogs

import (
	"regexp"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/iocutil"
	"golang.org/x/net/html"
)

// GenericParser is a reusable BlogParser for security blogs that publish
// Type/Indicator tables and/or defanged IOCs in narrative text.
// Each blog source creates one with its own name, feed URL, and keyword list.
type GenericParser struct {
	name            string
	feedURL         string
	keywords        []string
	excludeKeywords []string
}

// NewGenericParser returns a GenericParser for a blog that uses standard
// Type/Indicator or File/Hash tables and/or defanged IOC notation in text.
func NewGenericParser(name, feedURL string, keywords []string) *GenericParser {
	return &GenericParser{name: name, feedURL: feedURL, keywords: keywords}
}

// NewGenericParserWithExcludes is like NewGenericParser but also checks
// excludeKeywords — if any match the post title/description, the post is skipped.
func NewGenericParserWithExcludes(name, feedURL string, keywords, excludeKeywords []string) *GenericParser {
	return &GenericParser{name: name, feedURL: feedURL, keywords: keywords, excludeKeywords: excludeKeywords}
}

func (p *GenericParser) Name() string    { return p.name }
func (p *GenericParser) FeedURL() string { return p.feedURL }

func (p *GenericParser) MatchesPost(title, description string) bool {
	combined := strings.ToLower(title + " " + description)
	for _, kw := range p.excludeKeywords {
		if strings.Contains(combined, strings.ToLower(kw)) {
			return false
		}
	}
	for _, kw := range p.keywords {
		if strings.Contains(combined, kw) {
			return true
		}
	}
	return false
}

func (p *GenericParser) ParseIOCs(htmlStr string) ([]RawIOC, []AffectedPackage, error) {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return nil, nil, err
	}

	var iocs []RawIOC
	seen := map[string]bool{}

	add := func(ioc RawIOC) {
		key := ioc.Type + "|" + ioc.Value
		if !seen[key] {
			seen[key] = true
			iocs = append(iocs, ioc)
		}
	}

	// Walk all tables in the document
	var walkTables func(*html.Node)
	walkTables = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "table" {
			for _, ioc := range parseGenericTable(n, p.name) {
				add(ioc)
			}
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkTables(c)
		}
	}
	walkTables(doc)

	// Regex fallback — run on plain text only (not raw HTML) to avoid matching
	// CSS values, JS, HTML attributes, and tracking pixel parameters.
	var textBuf strings.Builder
	extractPlainText(doc, &textBuf)
	for _, ioc := range extractGenericRegexIOCs(textBuf.String(), p.name) {
		add(ioc)
	}

	return iocs, nil, nil
}

// genericTypeMapping maps common Type column values from security blogs.
var genericTypeMapping = map[string]string{
	"C2 Domain":    "domain",
	"Domain":       "domain",
	"Hostname":     "domain",
	"C2 IP":        "ip",
	"IP":           "ip",
	"IP Address":   "ip",
	"URL":          "url",
	"Payload URL":  "url",
	"SHA256":       "sha256",
	"SHA-256":      "sha256",
	"SHA1":         "sha1",
	"SHA-1":        "sha1",
	"MD5":          "md5",
	"Hash":         "sha256",
	"File Hash":    "sha256",
	"Mutex":        "mutex",
	"Registry Key": "registry_key",
	"Service Name": "service",
	"Named Pipe":   "named_pipe",
	"User Agent":   "user_agent",
	"Ransom Note":  "ransom_note_string",
	"Email":        "email",
	"CVE":          "cve_id",
}

func parseGenericTable(table *html.Node, source string) []RawIOC {
	var rows [][]*html.Node
	var collectRows func(*html.Node)
	collectRows = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "tr" {
			var cells []*html.Node
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.ElementNode && (c.Data == "td" || c.Data == "th") {
					cells = append(cells, c)
				}
			}
			if len(cells) > 0 {
				rows = append(rows, cells)
			}
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			collectRows(c)
		}
	}
	collectRows(table)

	if len(rows) < 2 {
		return nil
	}

	header := rows[0]
	if len(header) < 2 {
		return nil
	}
	col0 := strings.TrimSpace(nodeText(header[0]))
	col1 := strings.TrimSpace(nodeText(header[1]))

	isFileHash := strings.EqualFold(col0, "file") && (strings.EqualFold(col1, "hash") || strings.EqualFold(col1, "sha256"))
	isTypeIndicator := strings.EqualFold(col0, "type") && (strings.EqualFold(col1, "indicator") || strings.EqualFold(col1, "value") || strings.EqualFold(col1, "ioc"))
	isIndicatorType := (strings.EqualFold(col0, "indicator") || strings.EqualFold(col0, "ioc")) && strings.EqualFold(col1, "type")

	var iocs []RawIOC
	for _, row := range rows[1:] {
		if len(row) < 2 {
			continue
		}
		v0 := strings.TrimSpace(nodeText(row[0]))
		v1 := strings.TrimSpace(nodeText(row[1]))
		if v0 == "" && v1 == "" {
			continue
		}

		switch {
		case isFileHash:
			hashType := hashLengthType(v1)
			if hashType != "" {
				iocs = append(iocs, RawIOC{Type: hashType, Value: strings.ToLower(v1), Filename: v0, Source: source})
			}
		case isTypeIndicator:
			if iocType, ok := genericTypeMapping[v0]; ok {
				if clean, ok := NormalizeIOC(iocType, v1); ok {
					iocs = append(iocs, RawIOC{Type: iocType, Value: clean, Source: source})
				}
			}
		case isIndicatorType:
			if iocType, ok := genericTypeMapping[v1]; ok {
				if clean, ok := NormalizeIOC(iocType, v0); ok {
					iocs = append(iocs, RawIOC{Type: iocType, Value: clean, Source: source})
				}
			}
		}
	}
	return iocs
}

var (
	reGenericDefangedDomain = regexp.MustCompile(`[a-zA-Z0-9][-a-zA-Z0-9.]*\[\.\][a-zA-Z0-9.]+`)
	reGenericIP             = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reGenericSHA256         = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)
	reGenericSHA1           = regexp.MustCompile(`\b[0-9a-fA-F]{40}\b`)
	reGenericMD5            = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)

	// Scoped npm packages: @scope/name[@version] — version suffix is optional.
	reNPMScoped = regexp.MustCompile(`@[a-z0-9][-a-z0-9.]{0,100}/[a-z0-9][-a-z0-9._]{0,100}(?:@([^\s"'<>,]+))?`)
	// PyPI: pip install <name>[==version] patterns
	rePipInstall = regexp.MustCompile(`(?i)pip(?:3)?\s+install\s+([\w][\w.-]{1,100})(?:\s*([<>=!~^]{1,3}\s*[\w.*+!-]+(?:\s*,\s*[<>=!~^]{1,3}\s*[\w.*+!-]+)*))?`)
	// Bare pip version constraint: name==1.0.0 or name>=2.0 in requirements files.
	rePipVersioned = regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9._-]{1,100})\s*([<>=!~^]{1,3}\s*[\w.*+!-]+(?:\s*,\s*[<>=!~^]{1,3}\s*[\w.*+!-]+)*)\b`)
	// npm install <name>[@version] (unscoped)
	reNPMInstall = regexp.MustCompile(`(?i)npm\s+(?:install|i|add)\s+([\w][\w.-]{0,100})(?:@([^\s"'<>,]+))?`)
)

// NormalizeIOC cleans a raw IOC value extracted from a table cell. It
// delegates to the shared iocutil.Normalize so blog extraction and the
// downstream Sigma generator apply the same allowlist (ports, RFC1918,
// well-known DNS) instead of drifting independently.
//
// Table cells often contain annotations like "C2 IP · 142.11.206.73" or
// "https://evil.com (exfil endpoint)" — Normalize handles those.
var NormalizeIOC = iocutil.Normalize

// ExtractPackages scans plain text extracted from HTML for package name patterns.
// It catches scoped npm packages, npm install commands, pip install commands, and
// bare versioned pip requirements (name==x.y.z). Version constraints are captured
// when present so callers can populate AffectedVersions.
// Results are deduped; when the same package name appears with and without a version,
// the versioned entry wins.
func ExtractPackages(htmlStr string) []AffectedPackage {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return nil
	}
	var textBuf strings.Builder
	extractPlainText(doc, &textBuf)
	text := textBuf.String()

	// seen tracks best known version per "ecosystem|name" key.
	seen := map[string]string{} // key → version (empty = no version seen yet)
	var order []string           // insertion order for deterministic output

	add := func(eco, name, version string) {
		key := eco + "|" + strings.ToLower(name)
		existing, ok := seen[key]
		if !ok {
			order = append(order, key)
			seen[key] = version
		} else if existing == "" && version != "" {
			// Upgrade no-version entry with a versioned one.
			seen[key] = version
		}
	}

	for _, sub := range reNPMScoped.FindAllStringSubmatch(text, -1) {
		name := sub[0]
		version := ""
		if len(sub) > 1 {
			version = sub[1]
		}
		// Strip version suffix from the name string itself.
		if version != "" && strings.HasSuffix(name, "@"+version) {
			name = strings.TrimSuffix(name, "@"+version)
		}
		add("npm", name, version)
	}

	for _, sub := range reNPMInstall.FindAllStringSubmatch(text, -1) {
		name, version := sub[1], ""
		if len(sub) > 2 {
			version = sub[2]
		}
		add("npm", name, version)
	}

	for _, sub := range rePipInstall.FindAllStringSubmatch(text, -1) {
		name, version := sub[1], ""
		if len(sub) > 2 {
			version = strings.TrimSpace(sub[2])
		}
		add("pypi", name, version)
	}

	for _, sub := range rePipVersioned.FindAllStringSubmatch(text, -1) {
		name, version := sub[1], strings.TrimSpace(sub[2])
		// Only accept plausible package names — skip words that are clearly English prose.
		if looksLikePackageName(name) {
			add("pypi", name, version)
		}
	}

	out := make([]AffectedPackage, 0, len(order))
	for _, key := range order {
		parts := strings.SplitN(key, "|", 2)
		out = append(out, AffectedPackage{
			Ecosystem: parts[0],
			Name:      parts[1],
			Version:   seen[key],
		})
	}
	return out
}

// looksLikePackageName returns true for strings that plausibly name a Python package
// (contains a digit, hyphen, or underscore, or is all-lowercase with no spaces).
// Rejects common English words that happen to match the versioned-constraint regex.
func looksLikePackageName(s string) bool {
	if len(s) < 2 || len(s) > 80 {
		return false
	}
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			return false // prose word starting with capital
		}
		if r == '_' || r == '-' || (r >= '0' && r <= '9') {
			return true // underscore/hyphen/digit strongly suggests package name
		}
	}
	return true
}

func extractGenericRegexIOCs(htmlStr, source string) []RawIOC {
	var iocs []RawIOC
	for _, m := range reGenericDefangedDomain.FindAllString(htmlStr, -1) {
		domain := strings.ReplaceAll(m, "[.]", ".")
		iocs = append(iocs, RawIOC{Type: "domain", Value: domain, Source: source})
	}
	for _, m := range reGenericIP.FindAllString(htmlStr, -1) {
		iocs = append(iocs, RawIOC{Type: "ip", Value: m, Source: source})
	}
	for _, m := range reGenericSHA256.FindAllString(htmlStr, -1) {
		iocs = append(iocs, RawIOC{Type: "sha256", Value: strings.ToLower(m), Source: source})
	}
	for _, m := range reGenericSHA1.FindAllString(htmlStr, -1) {
		iocs = append(iocs, RawIOC{Type: "sha1", Value: strings.ToLower(m), Source: source})
	}
	for _, m := range reGenericMD5.FindAllString(htmlStr, -1) {
		iocs = append(iocs, RawIOC{Type: "md5", Value: strings.ToLower(m), Source: source})
	}
	return iocs
}

func hashLengthType(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch len(v) {
	case 64:
		return "sha256"
	case 40:
		return "sha1"
	case 32:
		return "md5"
	}
	return ""
}

// extractPlainText walks the parsed HTML tree and writes all text node content
// into sb, skipping <script> and <style> subtrees.
func extractPlainText(n *html.Node, sb *strings.Builder) {
	if n.Type == html.TextNode {
		sb.WriteString(n.Data)
		sb.WriteString(" ")
		return
	}
	if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style") {
		return
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		extractPlainText(c, sb)
	}
}

// nodeText returns the concatenated text content of an HTML node tree.
func nodeText(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var sb strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		sb.WriteString(nodeText(c))
	}
	return sb.String()
}
