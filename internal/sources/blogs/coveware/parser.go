package coveware

import "github.com/dragnet-dev/dragnet/internal/sources/blogs"

// Coveware now publishes a Squarespace RSS feed; the prior "no RSS feed"
// note in this file pre-dated that change.
var keywords = []string{
	"ransomware", "extortion", "ransom payment", "victim", "decryptor",
}

type Parser struct{ inner *blogs.GenericParser }

func New() *Parser {
	return &Parser{inner: blogs.NewGenericParser(
		"coveware",
		"https://www.coveware.com/blog?format=rss",
		keywords,
	)}
}

func (p *Parser) Name() string                        { return p.inner.Name() }
func (p *Parser) FeedURL() string                     { return p.inner.FeedURL() }
func (p *Parser) MatchesPost(title, desc string) bool { return p.inner.MatchesPost(title, desc) }
func (p *Parser) ParseIOCs(html string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	return p.inner.ParseIOCs(html)
}
