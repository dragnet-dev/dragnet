package aikido

import (
	"regexp"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/sources/blogs"
	"golang.org/x/net/html"
)

var (
	reSHA256Inline = regexp.MustCompile(`(?i)SHA-?256:\s*([a-f0-9]{64})`)
	reIP           = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
)

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) Name() string    { return "aikido" }
func (p *Parser) FeedURL() string { return "https://aikido.dev/blog/rss.xml" }

func (p *Parser) MatchesPost(title, description string) bool {
	return blogs.MatchesKeywords(title, description)
}

func (p *Parser) ParseIOCs(htmlStr string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return nil, nil, err
	}

	// Find H2 containing "Indicators Of Compromise"
	var iocH2 *html.Node
	var findH2 func(*html.Node)
	findH2 = func(n *html.Node) {
		if iocH2 != nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "h2" {
			txt := strings.ToLower(strings.TrimSpace(textContent(n)))
			if strings.Contains(txt, "indicators of compromise") || strings.Contains(txt, "indicators of compromise") {
				iocH2 = n
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			findH2(c)
		}
	}
	findH2(doc)

	if iocH2 == nil {
		return nil, nil, nil
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

	// Walk siblings after H2. Bold tags are section headers; following <ul> contains <li> items.
	currentSection := ""
	for sib := iocH2.NextSibling; sib != nil; sib = sib.NextSibling {
		if sib.Type != html.ElementNode {
			continue
		}
		if sib.Data == "h2" {
			break
		}
		if sib.Data == "h3" {
			// Sub-section (treat like section change)
			currentSection = strings.ToLower(strings.TrimSpace(textContent(sib)))
			continue
		}
		// Bold tag as section header (may be inside a <p> or directly)
		if sib.Data == "b" || sib.Data == "strong" {
			currentSection = strings.ToLower(strings.TrimSpace(textContent(sib)))
			continue
		}
		if sib.Data == "p" {
			// Check if p contains a bold/strong that is the section header
			boldChild := findFirstBold(sib)
			if boldChild != nil {
				currentSection = strings.ToLower(strings.TrimSpace(textContent(boldChild)))
				continue
			}
		}
		if sib.Data == "ul" {
			parseAikidoUL(sib, currentSection, p.Name(), addIOC)
			continue
		}
		// Bold tags or ULs may be nested in divs etc — walk children
		walkAikidoSiblingNode(sib, &currentSection, p.Name(), addIOC)
	}

	return iocs, nil, nil
}

// walkAikidoSiblingNode handles content nodes that may contain bold labels and ULs.
func walkAikidoSiblingNode(n *html.Node, currentSection *string, source string, addIOC func(blogs.RawIOC)) {
	if n.Type != html.ElementNode {
		return
	}
	if n.Data == "h2" {
		return
	}
	if n.Data == "b" || n.Data == "strong" {
		*currentSection = strings.ToLower(strings.TrimSpace(textContent(n)))
		return
	}
	if n.Data == "ul" {
		parseAikidoUL(n, *currentSection, source, addIOC)
		return
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walkAikidoSiblingNode(c, currentSection, source, addIOC)
	}
}

// findFirstBold returns the first <b> or <strong> child of a node.
func findFirstBold(n *html.Node) *html.Node {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && (c.Data == "b" || c.Data == "strong") {
			return c
		}
	}
	return nil
}

// parseAikidoUL processes <li> items according to the current section.
func parseAikidoUL(ul *html.Node, section, source string, addIOC func(blogs.RawIOC)) {
	for c := ul.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode || c.Data != "li" {
			continue
		}
		txt := strings.TrimSpace(textContent(c))
		if txt == "" {
			continue
		}
		parseAikidoItem(txt, section, source, addIOC)
	}
}

// parseAikidoItem classifies a single list item based on the current section.
func parseAikidoItem(txt, section, source string, addIOC func(blogs.RawIOC)) {
	switch {
	case strings.Contains(section, "files and payloads") || strings.Contains(section, "files"):
		// Extract inline SHA-256 hash if present
		m := reSHA256Inline.FindStringSubmatch(txt)
		if m != nil {
			hash := strings.ToLower(m[1])
			// Filename is text before "SHA"
			idx := strings.Index(strings.ToUpper(txt), "SHA")
			filename := ""
			if idx > 0 {
				filename = strings.TrimSpace(txt[:idx])
				// Remove trailing colon or dash
				filename = strings.TrimRight(filename, " -:")
			}
			addIOC(blogs.RawIOC{
				Type:     "sha256",
				Value:    hash,
				Filename: filename,
				Source:   source,
			})
			if filename != "" {
				addIOC(blogs.RawIOC{Type: "file_name", Value: filename, Source: source})
			}
		} else {
			// Plain filename
			addIOC(blogs.RawIOC{Type: "file_name", Value: txt, Source: source})
		}

	case strings.Contains(section, "network"):
		undefanged := undefang(txt)
		classify(undefanged, source, addIOC)

	case strings.Contains(section, "package markers") || strings.Contains(section, "package"):
		if strings.HasPrefix(txt, "github:") {
			addIOC(blogs.RawIOC{Type: "git_dep", Value: txt, Source: source})
		} else {
			addIOC(blogs.RawIOC{Type: "file_name", Value: txt, Source: source})
		}

	case strings.Contains(section, "campaign"):
		addIOC(blogs.RawIOC{Type: "campaign_marker", Value: txt, Source: source})

	default:
		// Best-effort: try to classify
		undefanged := undefang(txt)
		if strings.HasPrefix(undefanged, "http") {
			addIOC(blogs.RawIOC{Type: "url", Value: undefanged, Source: source})
		}
	}
}

// classify determines the IOC type for a network indicator.
func classify(val, source string, addIOC func(blogs.RawIOC)) {
	val = strings.TrimSpace(val)
	if val == "" {
		return
	}
	if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") {
		if clean, ok := blogs.NormalizeIOC("url", val); ok {
			addIOC(blogs.RawIOC{Type: "url", Value: clean, Source: source})
		}
		return
	}
	if ip := reIP.FindString(val); ip != "" {
		addIOC(blogs.RawIOC{Type: "ip", Value: ip, Source: source})
		return
	}
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
