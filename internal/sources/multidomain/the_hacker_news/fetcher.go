package the_hacker_news

import (
	"context"
	"time"

	"github.com/dragnet-dev/dragnet/internal/sources/multidomain/types"
	"github.com/mmcdole/gofeed"
)

const feedURL = "https://thehackernews.com/feeds/posts/default"

type Fetcher struct{}

func New() *Fetcher { return &Fetcher{} }

func (f *Fetcher) Name() string    { return "the_hacker_news" }
func (f *Fetcher) FeedURL() string { return feedURL }

func (f *Fetcher) FetchPosts(ctx context.Context, since time.Time) ([]types.BlogPost, error) {
	fp := gofeed.NewParser()
	feed, err := fp.ParseURLWithContext(feedURL, ctx)
	if err != nil {
		return nil, err
	}
	var posts []types.BlogPost
	for _, item := range feed.Items {
		if item.PublishedParsed != nil && item.PublishedParsed.Before(since) {
			continue
		}
		pub := time.Time{}
		if item.PublishedParsed != nil {
			pub = *item.PublishedParsed
		}
		posts = append(posts, types.BlogPost{
			Title:       item.Title,
			Description: item.Description,
			Content:     item.Content,
			Link:        item.Link,
			Published:   pub,
			Categories:  item.Categories,
		})
	}
	return posts, nil
}
