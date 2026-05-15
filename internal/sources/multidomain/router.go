package multidomain

import (
	"strings"

	"github.com/dragnet-dev/dragnet/internal/config"
	"github.com/dragnet-dev/dragnet/internal/sources/multidomain/types"
)

// BlogPost is a single post from a multi-domain RSS feed.
// Re-exported from the types sub-package for convenience.
type BlogPost = types.BlogPost

// MultiDomainFetcher fetches posts from a single multi-domain source.
// Re-exported from the types sub-package for convenience.
type MultiDomainFetcher = types.MultiDomainFetcher

// Router routes blog posts to modules via keyword scoring.
type Router struct {
	cfg config.MultiDomainSourceConfig
}

// New returns a Router for the given source config.
func New(cfg config.MultiDomainSourceConfig) *Router {
	return &Router{cfg: cfg}
}

// Route returns the module names that this post matches.
func (r *Router) Route(post BlogPost) []string {
	// Match on title and RSS categories only — body content produces too many
	// false positives (vendor marketing posts that mention threat terms in passing).
	content := strings.ToLower(post.Title + " " + strings.Join(post.Categories, " "))
	for _, kw := range r.cfg.GlobalExclude {
		if strings.Contains(content, strings.ToLower(kw)) {
			return nil
		}
	}
	var modules []string
	for _, rule := range r.cfg.Routing {
		if matches(content, rule) {
			modules = append(modules, rule.Module)
		}
	}
	return modules
}

func matches(content string, rule config.RoutingRule) bool {
	matched := false
	for _, kw := range rule.Include {
		if strings.Contains(content, strings.ToLower(kw)) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, kw := range rule.Exclude {
		if strings.Contains(content, strings.ToLower(kw)) {
			return false
		}
	}
	return true
}
