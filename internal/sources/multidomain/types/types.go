package types

import (
	"context"
	"time"
)

// BlogPost is a single post from a multi-domain RSS feed.
type BlogPost struct {
	Title       string
	Description string
	Content     string
	Link        string
	Published   time.Time
	Categories  []string
}

// MultiDomainFetcher fetches posts from a single multi-domain source.
type MultiDomainFetcher interface {
	Name() string
	FeedURL() string
	FetchPosts(ctx context.Context, since time.Time) ([]BlogPost, error)
}
