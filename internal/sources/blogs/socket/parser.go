package socket

import (
	"regexp"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/sources/blogs"
	"golang.org/x/net/html"
)

var (
	reHashLine = regexp.MustCompile(`(?i)^-\s+(SHA256|SHA1|MD5)\s+([a-f0-9]+)$`)
	reIP       = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
)

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Name() string    { return "socket" }
func (p *Parser) FeedURL() string { return "https://socket.dev/api/blog/feed.atom" }

func (p *Parser) MatchesPost(title, description string) bool {
	return blogs.MatchesKeywords(title, description)
}

func (p *Parser) ParseIOCs(htmlStr string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return nil, nil, err
	}

	// Find H2 "Indicators of Compromise (IOCs)"
	var iocH2 *html.Node
	var findH2 func(*html.Node)
	findH2 = func(n *html.Node) {
		if iocH2 != nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "h2" {
			txt := strings.ToLower(strings.TrimSpace(textContent(n)))
			if strings.Contains(txt, "indicators of compromise") {
				iocH2 = n
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			findH2(c)
		}
	}
	findH2(doc)

	var iocs []blogs.RawIOC
	seen := map[string]bool{}

	addIOC := func(ioc blogs.RawIOC) {
		key := ioc.Type + "|" + ioc.Value + "|" + ioc.Filename
		if !seen[key] {
			seen[key] = true
			iocs = append(iocs, ioc)
		}
	}

	if iocH2 != nil {
		// Walk siblings after the IOC H2
		currentSection := ""
		currentFilename := ""

		for sib := iocH2.NextSibling; sib != nil; sib = sib.NextSibling {
			if sib.Type != html.ElementNode {
				continue
			}
			if sib.Data == "h2" {
				break
			}
			if sib.Data == "h3" {
				currentSection = strings.ToLower(strings.TrimSpace(textContent(sib)))
				currentFilename = ""
				continue
			}

			// Section matching is substring-based — Socket has changed headings
			// like "Network" → "Network Indicators", "Files" → "File Hashes", etc.
			switch {
			case strings.Contains(currentSection, "file") || strings.Contains(currentSection, "hash"):
				parseSocketFilesNode(sib, &currentFilename, p.Name(), addIOC)
			case strings.Contains(currentSection, "network") || strings.Contains(currentSection, "domain") || strings.Contains(currentSection, "ip"):
				parseSocketNetworkNode(sib, p.Name(), addIOC)
			case strings.Contains(currentSection, "package") || strings.Contains(currentSection, "npm") || strings.Contains(currentSection, "supply"):
				for _, pkg := range blogs.ExtractPackages(textContent(sib)) {
					addIOC(blogs.RawIOC{Type: "package_" + pkg.Ecosystem, Value: pkg.Name, Source: p.Name()})
				}
			}
		}
	}

	// Fallback: extract scoped npm packages from full article text — catches
	// supply chain reports where IOCs are package names in narrative prose.
	for _, pkg := range blogs.ExtractPackages(htmlStr) {
		addIOC(blogs.RawIOC{Type: "package_" + pkg.Ecosystem, Value: pkg.Name, Source: p.Name()})
	}

	return iocs, nil, nil
}

// parseSocketFilesNode handles nodes under H3 "Files".
// Looks for bold/strong tags as filenames, and text lines matching hash patterns.
func parseSocketFilesNode(n *html.Node, currentFilename *string, source string, addIOC func(blogs.RawIOC)) {
	if n.Type == html.ElementNode && (n.Data == "b" || n.Data == "strong") {
		txt := strings.TrimSpace(textContent(n))
		if txt != "" {
			*currentFilename = txt
		}
		return
	}
	if n.Type == html.TextNode {
		lines := strings.Split(n.Data, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			m := reHashLine.FindStringSubmatch(line)
			if m != nil {
				algo := strings.ToLower(m[1])
				hash := strings.ToLower(m[2])
				addIOC(blogs.RawIOC{
					Type:     algo,
					Value:    hash,
					Filename: *currentFilename,
					Source:   source,
				})
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		parseSocketFilesNode(c, currentFilename, source, addIOC)
	}
}

// parseSocketNetworkNode handles nodes under H3 "Network".
func parseSocketNetworkNode(n *html.Node, source string, addIOC func(blogs.RawIOC)) {
	if n.Type == html.TextNode {
		lines := strings.Split(n.Data, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.Contains(line, "(DO NOT BLOCK)") {
				continue
			}
			// Un-defang
			undefanged := undefang(line)
			classify(undefanged, source, addIOC)
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		parseSocketNetworkNode(c, source, addIOC)
	}
}

// classify determines the IOC type for a network indicator and calls addIOC.
func classify(val, source string, addIOC func(blogs.RawIOC)) {
	val = strings.TrimSpace(val)
	if val == "" {
		return
	}
	if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") {
		addIOC(blogs.RawIOC{Type: "url", Value: val, Source: source})
		return
	}
	if reIP.MatchString(val) {
		addIOC(blogs.RawIOC{Type: "ip", Value: val, Source: source})
		return
	}
	// Treat as domain if it looks like one (contains a dot, no spaces)
	if strings.Contains(val, ".") && !strings.Contains(val, " ") {
		addIOC(blogs.RawIOC{Type: "domain", Value: val, Source: source})
	}
}

// undefang replaces defanged indicators with their real values.
func undefang(s string) string {
	s = strings.ReplaceAll(s, "[.]", ".")
	s = strings.ReplaceAll(s, "hxxps://", "https://")
	s = strings.ReplaceAll(s, "hxxp://", "http://")
	return s
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
