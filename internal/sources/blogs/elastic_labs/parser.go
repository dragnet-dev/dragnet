package elastic_labs

import (
	"regexp"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/sources/blogs"
	"golang.org/x/net/html"
)

var keywords = []string{
	"malware", "threat", "ioc", "indicators", "c2", "campaign",
	"ransomware", "backdoor", "apt", "elastic security",
}

var (
	reYARAName = regexp.MustCompile(`(?i)rule\s+(\w+)\s*\{`)
	rePreBlock = regexp.MustCompile(`(?s)<pre[^>]*>(.*?)</pre>`)
)

type Parser struct {
	inner *blogs.GenericParser
}

func New() *Parser {
	return &Parser{inner: blogs.NewGenericParser(
		"elastic_labs",
		"https://www.elastic.co/security-labs/rss/feed.xml",
		keywords,
	)}
}

func (p *Parser) Name() string    { return p.inner.Name() }
func (p *Parser) FeedURL() string { return p.inner.FeedURL() }

func (p *Parser) MatchesPost(title, desc string) bool {
	return p.inner.MatchesPost(title, desc)
}

func (p *Parser) ParseIOCs(htmlStr string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	// Standard table+regex extraction
	iocs, pkgs, err := p.inner.ParseIOCs(htmlStr)
	if err != nil {
		return nil, nil, err
	}

	seen := map[string]bool{}
	for _, ioc := range iocs {
		seen[ioc.Type+"|"+ioc.Value] = true
	}
	add := func(ioc blogs.RawIOC) {
		key := ioc.Type + "|" + ioc.Value
		if !seen[key] {
			seen[key] = true
			iocs = append(iocs, ioc)
		}
	}

	// Extract YARA rule names from <pre> blocks
	for _, match := range rePreBlock.FindAllStringSubmatch(htmlStr, -1) {
		block := match[1]
		// Unescape basic HTML entities
		block = strings.ReplaceAll(block, "&lt;", "<")
		block = strings.ReplaceAll(block, "&gt;", ">")
		block = strings.ReplaceAll(block, "&amp;", "&")
		// Strip HTML tags from <pre>
		doc, _ := html.Parse(strings.NewReader(block))
		text := extractText(doc)

		for _, m := range reYARAName.FindAllStringSubmatch(text, -1) {
			add(blogs.RawIOC{Type: "yara_rule_name", Value: m[1], Source: p.Name()})
		}
	}

	return iocs, pkgs, nil
}

func extractText(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var sb strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		sb.WriteString(extractText(c))
	}
	return sb.String()
}
