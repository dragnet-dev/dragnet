package talos

import "github.com/dragnet-dev/dragnet/internal/sources/blogs"

var keywords = []string{
	"malware", "ioc", "indicators of compromise", "threat actor", "campaign",
	"ransomware", "c2", "trojan", "exploit", "vulnerability",
}

type Parser struct{ inner *blogs.GenericParser }

func New() *Parser {
	return &Parser{inner: blogs.NewGenericParser(
		"talos",
		"https://blog.talosintelligence.com/rss/",
		keywords,
	)}
}

func (p *Parser) Name() string                        { return p.inner.Name() }
func (p *Parser) FeedURL() string                     { return p.inner.FeedURL() }
func (p *Parser) MatchesPost(title, desc string) bool { return p.inner.MatchesPost(title, desc) }
func (p *Parser) ParseIOCs(html string) ([]blogs.RawIOC, []blogs.AffectedPackage, error) {
	return p.inner.ParseIOCs(html)
}
