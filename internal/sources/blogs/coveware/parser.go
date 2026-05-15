package coveware

import (
	"strings"

	"github.com/dragnet-dev/dragnet/internal/sources/blogs"
)

var keywords = []string{
	"ransomware", "extortion", "ransom payment", "victim", "decryptor",
}

// Parser implements blogs.BlogParser for Coveware, which has no RSS feed.
// FeedURL returns an empty string; the caller is responsible for fetching
// and passing post HTML directly to ParseIOCs.
type Parser struct{ inner *blogs.GenericParser }

func New() *Parser {
	return &Parser{inner: blogs.NewGenericParser(
		"coveware",
		"",
		keywords,
	)}
}

func (p *Parser) Name() string    { return p.inner.Name() }
func (p *Parser) FeedURL() string { return "" }

func (p *Parser) MatchesPost(title, description string) bool {
	combined := strings.ToLower(title + " " + description)
	for _, kw := range keywords {
		if strings.Contains(combined, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

func (p *Parser) ParseIOCs(html string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	return p.inner.ParseIOCs(html)
}
