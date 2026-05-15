package unit42

import "github.com/dragnet-dev/dragnet/internal/sources/blogs"

var keywords = []string{
	"malware", "ransomware", "threat actor", "apt", "ioc",
	"indicators of compromise", "c2", "campaign", "backdoor",
	"trojan", "loader", "infostealer",
}

type Parser struct{ inner *blogs.GenericParser }

func New() *Parser {
	return &Parser{inner: blogs.NewGenericParser(
		"unit42",
		"https://unit42.paloaltonetworks.com/feed/",
		keywords,
	)}
}

func (p *Parser) Name() string                        { return p.inner.Name() }
func (p *Parser) FeedURL() string                     { return p.inner.FeedURL() }
func (p *Parser) MatchesPost(title, desc string) bool { return p.inner.MatchesPost(title, desc) }
func (p *Parser) ParseIOCs(html string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	return p.inner.ParseIOCs(html)
}
