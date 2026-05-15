package sonatype

import "github.com/dragnet-dev/dragnet/internal/sources/blogs"

var keywords = []string{
	"supply chain", "malicious package", "npm", "pypi", "maven", "open source security",
}

var noiseKeywords = []string{
	"how to", "playbook", "best practices", "guide", "whitepaper",
	"webinar", "sponsored", "advertorial",
}

type Parser struct{ inner *blogs.GenericParser }

func New() *Parser {
	return &Parser{inner: blogs.NewGenericParserWithExcludes(
		"sonatype",
		"https://blog.sonatype.com/rss.xml",
		keywords,
		noiseKeywords,
	)}
}

func (p *Parser) Name() string                        { return p.inner.Name() }
func (p *Parser) FeedURL() string                     { return p.inner.FeedURL() }
func (p *Parser) MatchesPost(title, desc string) bool { return p.inner.MatchesPost(title, desc) }
func (p *Parser) ParseIOCs(html string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	return p.inner.ParseIOCs(html)
}
