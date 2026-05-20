package blogs

// BlogParser extracts IOC data from a security blog's RSS feed posts.
type BlogParser interface {
	Name() string
	FeedURL() string
	// MatchesPost returns true when the post title/description indicates a
	// supply chain incident (npm, pypi, malicious package, etc.).
	MatchesPost(title, description string) bool
	// ParseIOCs extracts raw indicators and affected packages from post HTML.
	ParseIOCs(html string) ([]RawIOC, []AffectedPackage, error)
}

// RawIOC is an unvalidated indicator extracted from a blog post.
type RawIOC struct {
	// Type is one of: domain, ip, sha256, sha1, md5, url, service,
	// macos_persistence, linux_persistence, file_name, ide_artifact,
	// git_dep, campaign_marker
	Type     string
	Value    string
	Filename string // for hashes — which file this hash belongs to
	Context  string // package name if scoped to a specific package
	Source   string // blog name (e.g. "wiz", "socket")
}

// AffectedPackage is a package identified as affected in a blog post.
type AffectedPackage struct {
	Name      string
	Ecosystem string
	Version   string // specific version or constraint extracted from article text, if any
}

// supplyChainKeywords are matched against RSS post titles and descriptions to
// decide whether a post is relevant to supply chain security.
// Keep these specific enough to avoid false positives on cloud/infra posts.
// "compromised" alone is too broad — use "compromised package" instead.
var supplyChainKeywords = []string{
	"npm", "pypi", "cargo", "nuget", "rubygems", "packagist",
	"supply chain", "malicious package", "compromised package",
	"typosquat", "dependency confusion", "poisoned package",
	"malicious npm", "malicious pypi", "open source attack",
	"preinstall script", "postinstall script",
}

// MatchesKeywords is a helper that blog parsers can delegate to for standard
// supply chain keyword matching.
func MatchesKeywords(title, description string) bool {
	combined := title + " " + description
	for _, kw := range supplyChainKeywords {
		if containsFold(combined, kw) {
			return true
		}
	}
	return false
}

func containsFold(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if equalFold(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
