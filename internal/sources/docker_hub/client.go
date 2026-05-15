package docker_hub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const popularAPI = "https://hub.docker.com/v2/repositories/library?ordering=pull_count&page_size=%d"

// PopularImage is a Docker Hub official image ranked by weekly pulls.
type PopularImage struct {
	Repository  string `json:"name"`
	WeeklyPulls int64  `json:"pull_count"`
	Description string `json:"description"`
}

type Client struct {
	http *http.Client
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 30 * time.Second}}
}

// FetchPopular returns the top-n most-pulled official Docker Hub images.
func (c *Client) FetchPopular(ctx context.Context, n int) ([]PopularImage, error) {
	if n <= 0 {
		n = 100
	}
	url := fmt.Sprintf(popularAPI, n)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker hub: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Results []PopularImage `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("docker hub: decode: %w", err)
	}
	return body.Results, nil
}
