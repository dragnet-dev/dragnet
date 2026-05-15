package horizon3

import "github.com/dragnet-dev/dragnet/internal/sources/blogs"

var keywords = []string{
	"CVE-", "vulnerability", "exploit", "PoC", "remote code execution", "NodeZero",
}

var excludeKeywords = []string{
	"NodeZero for", "NodeZero is", "NodeZero now",
	"seconds to breach", "time to breach", "compliance report",
	"product launch", "announces", "introduces",
}

type Parser struct{ inner *blogs.GenericParser }

func New() *Parser {
	return &Parser{inner: blogs.NewGenericParserWithExcludes(
		"horizon3",
		"https://horizon3.ai/feed",
		keywords,
		excludeKeywords,
	)}
}

func (p *Parser) Name() string                        { return p.inner.Name() }
func (p *Parser) FeedURL() string                     { return p.inner.FeedURL() }
func (p *Parser) MatchesPost(title, desc string) bool { return p.inner.MatchesPost(title, desc) }
func (p *Parser) ParseIOCs(html string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	return p.inner.ParseIOCs(html)
}
