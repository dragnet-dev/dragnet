package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const apiURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// Client fetches CVE records from the NVD REST API.
type Client struct {
	http *http.Client
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) Name() string { return "nvd" }

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID        string `json:"id"`
			Published string `json:"published"`
			// NVD API v2.0: descriptions is a flat array, not a nested object.
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	params := url.Values{}
	params.Set("pubStartDate", since.UTC().Format("2006-01-02T15:04:05.000"))
	params.Set("pubEndDate", time.Now().UTC().Format("2006-01-02T15:04:05.000"))
	params.Set("resultsPerPage", "100")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dragnet-bot/1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd: %w", err)
	}
	defer resp.Body.Close()

	var data nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("nvd decode: %w", err)
	}

	var incidents []*incident.Incident
	for _, v := range data.Vulnerabilities {
		cve := v.CVE
		desc := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}

		if strings.HasPrefix(desc, "** REJECT **") || strings.HasPrefix(desc, "** DISPUTED **") {
			continue
		}

		var refs []string
		for _, r := range cve.References {
			refs = append(refs, r.URL)
		}

		ext := &incident.CVEExtension{
			CVEID: cve.ID,
		}
		if len(cve.Metrics.CVSSV31) > 0 {
			ext.CVSSScore = cve.Metrics.CVSSV31[0].CVSSData.BaseScore
			ext.CVSSVector = cve.Metrics.CVSSV31[0].CVSSData.VectorString
		}

		// Keep unscored CVEs (may be new zero-days); drop known low/medium.
		if ext.CVSSScore > 0 && ext.CVSSScore < 7.0 {
			continue
		}

		severity := cvssToSeverity(ext.CVSSScore)
		inc := &incident.Incident{
			ID:          "nvd-" + cve.ID,
			AttackType:  "vulnerability",
			Severity:    severity,
			Description: desc,
			References:  refs,
			CVEExt:      ext,
		}
		incidents = append(incidents, inc)
	}
	return incidents, nil
}

func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}
