package ransomware_live

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const feedURL = "https://api.ransomware.live/recentvictims"

// Client fetches recent ransomware victims from the ransomware.live JSON API.
type Client struct {
	http *http.Client
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) Name() string { return "ransomware_live" }

type victim struct {
	Group       string `json:"group_name"`
	Victim      string `json:"victim_name"`
	Country     string `json:"country"`
	Description string `json:"description"`
	Published   string `json:"published"`
	URL         string `json:"url"`
}

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dragnet-bot/1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ransomware.live: %w", err)
	}
	defer resp.Body.Close()

	var victims []victim
	if err := json.NewDecoder(resp.Body).Decode(&victims); err != nil {
		return nil, fmt.Errorf("ransomware.live decode: %w", err)
	}

	var incidents []*incident.Incident
	for _, v := range victims {
		if v.Published != "" {
			t, err := time.Parse("2006-01-02 15:04:05.999999", v.Published)
			if err == nil && t.Before(since) {
				continue
			}
		}

		inc := &incident.Incident{
			ID:          "ransomware_live-" + slugify(v.Victim),
			AttackType:  "ransomware",
			Description: v.Description,
			RansomwareExt: &incident.RansomwareExtension{
				RansomwareGroup:   v.Group,
				TargetedCountries: countryList(v.Country),
			},
		}
		if v.URL != "" {
			inc.References = []string{v.URL}
		}
		incidents = append(incidents, inc)
	}
	return incidents, nil
}

func slugify(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			out = append(out, c)
		} else if c >= 'A' && c <= 'Z' {
			out = append(out, c+('a'-'A'))
		} else {
			out = append(out, '-')
		}
	}
	return string(out)
}

func countryList(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
