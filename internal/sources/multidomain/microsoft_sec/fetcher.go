package microsoft_sec

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dragnet-dev/dragnet/internal/sources/multidomain/types"
	"github.com/mmcdole/gofeed"
)

const feedURL = "https://www.microsoft.com/en-us/security/blog/feed/"

var httpClient = &http.Client{Timeout: 30 * time.Second}

type Fetcher struct{}

func New() *Fetcher { return &Fetcher{} }

func (f *Fetcher) Name() string    { return "microsoft_sec" }
func (f *Fetcher) FeedURL() string { return feedURL }

func (f *Fetcher) FetchPosts(ctx context.Context, since time.Time) ([]types.BlogPost, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("User-Agent", "Dragnet-CTI-Bot/1.0 (+https://github.com/dragnet-dev/dragnet)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", feedURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, feedURL)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	fp := gofeed.NewParser()
	feed, err := fp.ParseString(string(body))
	if err != nil {
		return nil, fmt.Errorf("parse feed: %w", err)
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
