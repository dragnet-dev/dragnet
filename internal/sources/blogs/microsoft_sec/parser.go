package microsoft_sec

import "github.com/dragnet-dev/dragnet/internal/sources/blogs"

var keywords = []string{
	"ransomware", "malware", "threat actor", "ioc", "indicators",
	"microsoft threat intelligence", "c2", "campaign", "apt",
}

type Parser struct{ inner *blogs.GenericParser }

func New() *Parser {
	return &Parser{inner: blogs.NewGenericParser(
		"microsoft_sec",
		"https://www.microsoft.com/security/blog/feed/",
		keywords,
	)}
}

func (p *Parser) Name() string                        { return p.inner.Name() }
func (p *Parser) FeedURL() string                     { return p.inner.FeedURL() }
func (p *Parser) MatchesPost(title, desc string) bool { return p.inner.MatchesPost(title, desc) }
func (p *Parser) ParseIOCs(html string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	return p.inner.ParseIOCs(html)
}
