package stepsecurity

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

func (p *Parser) Name() string    { return "stepsecurity" }
func (p *Parser) FeedURL() string { return "https://www.stepsecurity.io/blog/rss.xml" }

func (p *Parser) MatchesPost(title, description string) bool {
	return blogs.MatchesKeywords(title, description)
}

func (p *Parser) ParseIOCs(htmlStr string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return nil, nil, err
	}

	// Find H2 or H3 containing IOC-related text
	var iocHeader *html.Node
	var iocHeaderTag string
	var findIOCHeader func(*html.Node)
	findIOCHeader = func(n *html.Node) {
		if iocHeader != nil {
			return
		}
		if n.Type == html.ElementNode && (n.Data == "h2" || n.Data == "h3") {
			txt := strings.ToLower(strings.TrimSpace(textContent(n)))
			if strings.Contains(txt, "indicators of compromise") || strings.Contains(txt, "ioc") {
				iocHeader = n
				iocHeaderTag = n.Data
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			findIOCHeader(c)
		}
	}
	findIOCHeader(doc)

	if iocHeader == nil {
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

	// Walk siblings after the IOC header
	currentSection := ""
	for sib := iocHeader.NextSibling; sib != nil; sib = sib.NextSibling {
		if sib.Type != html.ElementNode {
			continue
		}
		// Stop at same-level or higher heading
		if sib.Data == "h2" || (iocHeaderTag == "h3" && sib.Data == "h3") {
			break
		}
		if sib.Data == "h3" || sib.Data == "h4" {
			currentSection = strings.ToLower(strings.TrimSpace(textContent(sib)))
			continue
		}
		if sib.Data == "b" || sib.Data == "strong" {
			currentSection = strings.ToLower(strings.TrimSpace(textContent(sib)))
			continue
		}
		if sib.Data == "p" {
			boldChild := findFirstBold(sib)
			if boldChild != nil {
				currentSection = strings.ToLower(strings.TrimSpace(textContent(boldChild)))
				continue
			}
		}
		if sib.Data == "ul" {
			parseStepSecurityUL(sib, currentSection, p.Name(), addIOC)
			continue
		}
		// Walk nested content
		walkStepSecurityNode(sib, &currentSection, p.Name(), addIOC)
	}

	return iocs, nil, nil
}

// walkStepSecurityNode handles nested content nodes.
func walkStepSecurityNode(n *html.Node, currentSection *string, source string, addIOC func(blogs.RawIOC)) {
	if n.Type != html.ElementNode {
		return
	}
	if n.Data == "h2" || n.Data == "h3" {
		return
	}
	if n.Data == "b" || n.Data == "strong" {
		*currentSection = strings.ToLower(strings.TrimSpace(textContent(n)))
		return
	}
	if n.Data == "ul" {
		parseStepSecurityUL(n, *currentSection, source, addIOC)
		return
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walkStepSecurityNode(c, currentSection, source, addIOC)
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

// parseStepSecurityUL processes <li> items according to the current section.
func parseStepSecurityUL(ul *html.Node, section, source string, addIOC func(blogs.RawIOC)) {
	for c := ul.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode || c.Data != "li" {
			continue
		}
		txt := strings.TrimSpace(textContent(c))
		if txt == "" {
			continue
		}
		parseStepSecurityItem(txt, section, source, addIOC)
	}
}

// parseStepSecurityItem classifies a single list item.
func parseStepSecurityItem(txt, section, source string, addIOC func(blogs.RawIOC)) {
	switch {
	case strings.Contains(section, "files") || strings.Contains(section, "payload") || strings.Contains(section, "hash"):
		m := reSHA256Inline.FindStringSubmatch(txt)
		if m != nil {
			hash := strings.ToLower(m[1])
			idx := strings.Index(strings.ToUpper(txt), "SHA")
			filename := ""
			if idx > 0 {
				filename = strings.TrimSpace(txt[:idx])
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
			addIOC(blogs.RawIOC{Type: "file_name", Value: txt, Source: source})
		}

	case strings.Contains(section, "network") || strings.Contains(section, "domain") || strings.Contains(section, "ip") || strings.Contains(section, "url"):
		undefanged := undefang(txt)
		classify(undefanged, source, addIOC)

	case strings.Contains(section, "package"):
		if strings.HasPrefix(txt, "github:") {
			addIOC(blogs.RawIOC{Type: "git_dep", Value: txt, Source: source})
		} else {
			addIOC(blogs.RawIOC{Type: "file_name", Value: txt, Source: source})
		}

	case strings.Contains(section, "campaign"):
		addIOC(blogs.RawIOC{Type: "campaign_marker", Value: txt, Source: source})

	default:
		// Try to classify by content
		undefanged := undefang(txt)
		if strings.HasPrefix(undefanged, "http") {
			addIOC(blogs.RawIOC{Type: "url", Value: undefanged, Source: source})
		} else {
			m := reSHA256Inline.FindStringSubmatch(txt)
			if m != nil {
				addIOC(blogs.RawIOC{Type: "sha256", Value: strings.ToLower(m[1]), Source: source})
			}
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
