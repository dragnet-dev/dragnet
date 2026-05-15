package attackerkb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const apiURL = "https://api.attackerkb.com/v1/topics"

// Client fetches exploitation assessment data from AttackerKB.
type Client struct {
	http   *http.Client
	apiKey string
}

// New constructs a Client. If ATTACKERKB_API_KEY is set in the environment,
// it is used to authenticate requests. Without it the API serves a small
// rate-limited subset and returns 401 on extended requests; we surface that
// error message at fetch time.
func New() *Client {
	return &Client{
		http:   &http.Client{Timeout: 30 * time.Second},
		apiKey: os.Getenv("ATTACKERKB_API_KEY"),
	}
}

func (c *Client) Name() string { return "attackerkb" }

type akbResponse struct {
	Data []struct {
		Name        string  `json:"name"`
		Document    string  `json:"document"`
		CreatedAt   string  `json:"created_at"`
		Score       float64 `json:"score"`
		EditorScore float64 `json:"editor_score"`
	} `json:"data"`
}

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	params := url.Values{}
	params.Set("after", since.UTC().Format(time.RFC3339))
	params.Set("size", "100")
	// Only topics with exploitation evidence
	params.Set("q", "exploited")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dragnet-bot/1.0")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "ApiKey "+c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("attackerkb: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("attackerkb: API key required (set ATTACKERKB_API_KEY)")
	}

	var data akbResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("attackerkb decode: %w", err)
	}

	var incidents []*incident.Incident
	for _, topic := range data.Data {
		inc := &incident.Incident{
			ID:          "attackerkb-" + slugify(topic.Name),
			AttackType:  "vulnerability",
			Severity:    akbScoreToSeverity(topic.Score),
			Description: topic.Document,
			CVEExt: &incident.CVEExtension{
				CVEID:         topic.Name,
				ExploitPublic: topic.Score > 0,
			},
		}
		incidents = append(incidents, inc)
	}
	return incidents, nil
}

func akbScoreToSeverity(score float64) string {
	switch {
	case score >= 4.0:
		return "critical"
	case score >= 3.0:
		return "high"
	case score >= 2.0:
		return "medium"
	default:
		return "low"
	}
}

func slugify(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			out = append(out, c)
		} else if c >= 'A' && c <= 'Z' {
			out = append(out, c+('a'-'A'))
		} else {
			out = append(out, '-')
		}
	}
	return string(out)
}
