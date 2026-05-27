package phylum

import (
	"regexp"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/sources/blogs"
)

var keywords = []string{
	"malicious package", "supply chain", "npm", "pypi", "cargo", "nuget", "rubygems", "typosquat",
}

// reCampaign matches campaign/operation/cluster mentions in Phylum report text.
// Phylum attribution callouts typically look like "Attribution: Operation GitVenom"
// or "Campaign: XYZ Cluster".
var reCampaign = regexp.MustCompile(`(?i)(?:campaign|operation|cluster|attribution)\s*:?\s*([A-Z][A-Za-z0-9][A-Za-z0-9 \-]{2,38})`)

type Parser struct{ inner *blogs.GenericParser }

func New() *Parser {
	return &Parser{inner: blogs.NewGenericParser(
		"phylum",
		"https://blog.phylum.io/rss.xml",
		keywords,
	)}
}

func (p *Parser) Name() string                        { return p.inner.Name() }
func (p *Parser) FeedURL() string                     { return p.inner.FeedURL() }
func (p *Parser) MatchesPost(title, desc string) bool { return p.inner.MatchesPost(title, desc) }
func (p *Parser) ParseIOCs(html string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	iocs, pkgs, err := p.inner.ParseIOCs(html)
	if err != nil {
		return nil, nil, err
	}
	if m := reCampaign.FindStringSubmatch(html); m != nil {
		name := strings.TrimSpace(m[1])
		if name != "" {
			iocs = append(iocs, blogs.RawIOC{Type: "campaign_marker", Value: name, Source: p.inner.Name()})
		}
	}
	return iocs, pkgs, nil
}
