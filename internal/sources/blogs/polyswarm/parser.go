package polyswarm

import "github.com/dragnet-dev/dragnet/internal/sources/blogs"

var malwareKeywords = []string{
	"malware", "trojan", "loader", "infostealer", "backdoor", "rat",
	"botnet", "dropper", "cryptominer", "wiper", "indicators of compromise",
	"ioc", "c2", "command and control", "threat actor",
}

type Parser struct{ inner *blogs.GenericParser }

func New() *Parser {
	return &Parser{inner: blogs.NewGenericParser(
		"polyswarm",
		"https://polyswarm.network/blog/feed",
		malwareKeywords,
	)}
}

func (p *Parser) Name() string                        { return p.inner.Name() }
func (p *Parser) FeedURL() string                     { return p.inner.FeedURL() }
func (p *Parser) MatchesPost(title, desc string) bool { return p.inner.MatchesPost(title, desc) }
func (p *Parser) ParseIOCs(html string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	return p.inner.ParseIOCs(html)
}
