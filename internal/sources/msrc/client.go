package msrc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

// Client fetches CVE data from the Microsoft Security Response Center API.
type Client struct {
	http *http.Client
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) Name() string { return "msrc" }

type msrcUpdate struct {
	ID                 string `json:"ID"`
	Alias              string `json:"Alias"`
	DocumentTitle      string `json:"DocumentTitle"`
	Severity           string `json:"Severity"`
	InitialReleaseDate string `json:"InitialReleaseDate"`
}

type msrcResponse struct {
	Value []msrcUpdate `json:"value"`
}

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	// MSRC uses a monthly update guide; fetch the current month's data
	monthKey := since.UTC().Format("2006-Jan")
	apiURL := fmt.Sprintf("https://api.msrc.microsoft.com/cvrf/v2.0/updates/%s", monthKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dragnet-bot/1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("msrc: %w", err)
	}
	defer resp.Body.Close()

	var data msrcResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("msrc decode: %w", err)
	}

	var incidents []*incident.Incident
	for _, u := range data.Value {
		if u.Alias == "" {
			continue
		}
		inc := &incident.Incident{
			ID:          "msrc-" + u.Alias,
			AttackType:  "vulnerability",
			Severity:    msrcSeverity(u.Severity),
			Description: u.DocumentTitle,
			CVEExt: &incident.CVEExtension{
				CVEID: u.Alias,
			},
		}
		incidents = append(incidents, inc)
	}
	return incidents, nil
}

func msrcSeverity(s string) string {
	switch s {
	case "Critical":
		return "critical"
	case "Important":
		return "high"
	case "Moderate":
		return "medium"
	default:
		return "low"
	}
}
