package project_zero

import "github.com/dragnet-dev/dragnet/internal/sources/blogs"

var keywords = []string{
	"vulnerability", "exploit", "cve", "rce", "0day", "zero-day",
	"memory corruption", "use-after-free", "buffer overflow", "attack",
}

type Parser struct{ inner *blogs.GenericParser }

func New() *Parser {
	return &Parser{inner: blogs.NewGenericParser(
		"project_zero",
		// Blog moved from blogspot to projectzero.google in 2025.
		"https://projectzero.google/feed.xml",
		keywords,
	)}
}

func (p *Parser) Name() string                        { return p.inner.Name() }
func (p *Parser) FeedURL() string                     { return p.inner.FeedURL() }
func (p *Parser) MatchesPost(title, desc string) bool { return p.inner.MatchesPost(title, desc) }
func (p *Parser) ParseIOCs(html string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	return p.inner.ParseIOCs(html)
}
