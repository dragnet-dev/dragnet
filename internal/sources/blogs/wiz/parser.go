package wiz

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/sources/blogs"
	"golang.org/x/net/html"
)

var (
	reDefangedDomain = regexp.MustCompile(`[a-zA-Z0-9.-]+\[\.\][a-zA-Z0-9.-]+`)
	reRawIP          = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reSHA256         = regexp.MustCompile(`\b[a-f0-9]{64}\b`)
	reSHA1           = regexp.MustCompile(`\b[a-f0-9]{40}\b`)
	reMD5            = regexp.MustCompile(`\b[a-f0-9]{32}\b`)
)

// typeMapping maps Wiz "Type" column values to RawIOC.Type values.
var typeMapping = map[string]string{
	"C2 Domain":         "domain",
	"Domain":            "domain",
	"C2 IP":             "ip",
	"IP Address":        "ip",
	"Payload URL":       "url",
	"SHA256":            "sha256",
	"SHA1":              "sha1",
	"MD5":               "md5",
	"Service Name":      "service",
	"macOS Persistence": "macos_persistence",
	"Linux Persistence": "linux_persistence",
	"Runtime Artifact":  "file_name",
	"Path":              "ide_artifact",
}

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Name() string    { return "wiz" }
func (p *Parser) FeedURL() string { return "https://www.wiz.io/feed/rss.xml" }

func (p *Parser) MatchesPost(title, description string) bool {
	return blogs.MatchesKeywords(title, description)
}

func (p *Parser) ParseIOCs(htmlStr string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return nil, nil, err
	}

	var iocs []blogs.RawIOC
	seen := map[string]bool{}

	addIOC := func(ioc blogs.RawIOC) {
		key := ioc.Type + "|" + ioc.Value + "|" + ioc.Filename
		if !seen[key] {
			seen[key] = true
			iocs = append(iocs, ioc)
		}
	}

	// Find the H2 node containing "Indicators of compromise"
	var iocSection *html.Node
	var findH2 func(*html.Node)
	findH2 = func(n *html.Node) {
		if iocSection != nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "h2" {
			if containsFoldStr(textContent(n), "indicators of compromise") {
				iocSection = n
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			findH2(c)
		}
	}
	findH2(doc)

	if iocSection == nil {
		return nil, nil, nil
	}

	// Walk siblings after the H2 to find H3s and tables
	currentPkg := ""
	for sib := iocSection.NextSibling; sib != nil; sib = sib.NextSibling {
		if sib.Type != html.ElementNode {
			continue
		}
		// Stop at another H2
		if sib.Data == "h2" {
			break
		}
		if sib.Data == "h3" {
			currentPkg = strings.TrimSpace(textContent(sib))
			continue
		}
		if sib.Data == "table" {
			tableIOCs := parseWizTable(sib, currentPkg, p.Name())
			for _, ioc := range tableIOCs {
				addIOC(ioc)
			}
			continue
		}
		// Also look for tables nested inside divs etc.
		findTablesIn(sib, currentPkg, p.Name(), addIOC)
	}

	// Regex pass scoped to the IOC section text only (not full HTML)
	var iocText strings.Builder
	for sib := iocSection.NextSibling; sib != nil; sib = sib.NextSibling {
		if sib.Type == html.ElementNode && sib.Data == "h2" {
			break
		}
		iocText.WriteString(textContent(sib))
		iocText.WriteString(" ")
	}
	for _, ioc := range extractRegexIOCs(iocText.String(), p.Name()) {
		addIOC(ioc)
	}

	return iocs, nil, nil
}

// findTablesIn recursively finds tables within a node and parses them.
func findTablesIn(n *html.Node, pkg, source string, addIOC func(blogs.RawIOC)) {
	if n.Type == html.ElementNode && n.Data == "table" {
		for _, ioc := range parseWizTable(n, pkg, source) {
			addIOC(ioc)
		}
		return
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		findTablesIn(c, pkg, source, addIOC)
	}
}

// parseWizTable parses a Wiz blog table. It handles two table types:
// 1. File/Hash tables: columns "File" and "Hash"
// 2. Type/Indicator tables: columns "Type" and "Indicator"
func parseWizTable(table *html.Node, pkg, source string) []blogs.RawIOC {
	// Collect all rows
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

	if len(rows) == 0 {
		return nil
	}

	// Determine table type from header row
	if len(rows) < 2 {
		return nil
	}
	headerRow := rows[0]
	if len(headerRow) < 2 {
		return nil
	}
	col0 := strings.TrimSpace(textContent(headerRow[0]))
	col1 := strings.TrimSpace(textContent(headerRow[1]))

	var iocs []blogs.RawIOC

	isFileHash := strings.EqualFold(col0, "file") && strings.EqualFold(col1, "hash")
	isTypeIndicator := strings.EqualFold(col0, "type") && strings.EqualFold(col1, "indicator")

	for _, row := range rows[1:] {
		if len(row) < 2 {
			continue
		}
		v0 := strings.TrimSpace(textContent(row[0]))
		v1 := strings.TrimSpace(textContent(row[1]))
		if v0 == "" && v1 == "" {
			continue
		}

		if isFileHash {
			// v0 = filename, v1 = hash value; detect hash type from length
			hashType := hashTypeFromValue(v1)
			if hashType != "" {
				iocs = append(iocs, blogs.RawIOC{
					Type:     hashType,
					Value:    strings.ToLower(v1),
					Filename: v0,
					Context:  pkg,
					Source:   source,
				})
			}
		} else if isTypeIndicator {
			iocType, ok := typeMapping[v0]
			if !ok {
				continue
			}
			if clean, ok := blogs.NormalizeIOC(iocType, v1); ok {
				iocs = append(iocs, blogs.RawIOC{
					Type:    iocType,
					Value:   clean,
					Context: pkg,
					Source:  source,
				})
			}
		} else {
			// Generic: try type mapping on col0 header
			if iocType, ok := typeMapping[col0]; ok {
				if clean, ok := blogs.NormalizeIOC(iocType, v0); ok {
					iocs = append(iocs, blogs.RawIOC{
						Type:    iocType,
						Value:   clean,
						Context: pkg,
						Source:  source,
					})
				}
			}
		}
	}
	return iocs
}

// hashTypeFromValue detects hash type by length (hex chars).
func hashTypeFromValue(v string) string {
	v = strings.ToLower(v)
	switch len(v) {
	case 64:
		if isHex(v) {
			return "sha256"
		}
	case 40:
		if isHex(v) {
			return "sha1"
		}
	case 32:
		if isHex(v) {
			return "md5"
		}
	}
	return ""
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// isValidIPv4 returns true only when all four dotted octets are 0-255.
func isValidIPv4(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// extractRegexIOCs scans raw HTML text for IOCs not captured by table parsing.
func extractRegexIOCs(htmlStr, source string) []blogs.RawIOC {
	var iocs []blogs.RawIOC

	// Defanged domains
	for _, m := range reDefangedDomain.FindAllString(htmlStr, -1) {
		domain := strings.ReplaceAll(m, "[.]", ".")
		iocs = append(iocs, blogs.RawIOC{Type: "domain", Value: domain, Source: source})
	}

	// Raw IPs — validate each octet is 0-255 to reject false positives
	for _, m := range reRawIP.FindAllString(htmlStr, -1) {
		if isValidIPv4(m) {
			iocs = append(iocs, blogs.RawIOC{Type: "ip", Value: m, Source: source})
		}
	}

	// SHA256
	for _, m := range reSHA256.FindAllString(htmlStr, -1) {
		iocs = append(iocs, blogs.RawIOC{Type: "sha256", Value: m, Source: source})
	}

	// SHA1 (must not be sha256)
	for _, m := range reSHA1.FindAllString(htmlStr, -1) {
		iocs = append(iocs, blogs.RawIOC{Type: "sha1", Value: m, Source: source})
	}

	// MD5 (must not be sha1 or sha256)
	for _, m := range reMD5.FindAllString(htmlStr, -1) {
		iocs = append(iocs, blogs.RawIOC{Type: "md5", Value: m, Source: source})
	}

	return iocs
}

// textContent returns the concatenated text of a node and all descendants.
func textContent(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var sb strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		sb.WriteString(textContent(c))
	}
	return sb.String()
}

func containsFoldStr(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
