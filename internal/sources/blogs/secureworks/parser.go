package secureworks

import "github.com/dragnet-dev/dragnet/internal/sources/blogs"

var keywords = []string{
	"malware", "ransomware", "threat group", "gold", "bronze", "iron",
	"ioc", "indicators", "c2", "campaign", "apt",
}

type Parser struct{ inner *blogs.GenericParser }

func New() *Parser {
	// secureworks.com was acquired by Sophos; blog now lives at sophos.com.
	return &Parser{inner: blogs.NewGenericParser(
		"secureworks",
		"https://www.sophos.com/en-us/blog/feed",
		keywords,
	)}
}

func (p *Parser) Name() string                        { return p.inner.Name() }
func (p *Parser) FeedURL() string                     { return p.inner.FeedURL() }
func (p *Parser) MatchesPost(title, desc string) bool { return p.inner.MatchesPost(title, desc) }
func (p *Parser) ParseIOCs(html string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	return p.inner.ParseIOCs(html)
}
