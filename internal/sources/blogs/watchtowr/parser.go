package watchtowr

import "github.com/dragnet-dev/dragnet/internal/sources/blogs"

var keywords = []string{
	"CVE-", "vulnerability", "exploitation", "zero-day", "PoC", "attack chain",
}

type Parser struct{ inner *blogs.GenericParser }

func New() *Parser {
	return &Parser{inner: blogs.NewGenericParser(
		"watchtowr",
		"https://labs.watchtowr.com/feed/",
		keywords,
	)}
}

func (p *Parser) Name() string                        { return p.inner.Name() }
func (p *Parser) FeedURL() string                     { return p.inner.FeedURL() }
func (p *Parser) MatchesPost(title, desc string) bool { return p.inner.MatchesPost(title, desc) }
func (p *Parser) ParseIOCs(html string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	return p.inner.ParseIOCs(html)
}
