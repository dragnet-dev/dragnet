package github_actions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const (
	osvAPIURL  = "https://api.osv.dev/v1/query"
	githubAPI  = "https://api.github.com"
	ecosystem  = "GitHub Actions"
)

// PopularAction is one entry in state/popular_actions.json.
type PopularAction struct {
	Name     string `json:"name"`
	Official bool   `json:"official"`
	LastSHA  string `json:"last_sha,omitempty"`
}

// popularActionList is the on-disk format for state/popular_actions.json.
type popularActionList struct {
	Generated time.Time       `json:"generated"`
	Actions   []PopularAction `json:"actions"`
}

// Client fetches GitHub Actions advisories (via OSV) and monitors popular action SHA changes.
type Client struct {
	http        *http.Client
	popularPath string
}

func New(popularPath string) *Client {
	return &Client{
		http:        &http.Client{Timeout: 30 * time.Second},
		popularPath: popularPath,
	}
}

func (c *Client) Name() string { return "github_actions" }

func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	var out []*incident.Incident

	adv, err := c.queryOSVAdvisories(ctx, since)
	if err != nil {
		log.Printf("[github_actions] OSV query error: %v", err)
	} else {
		out = append(out, adv...)
	}

	popular, err := c.loadPopularActions()
	if err != nil {
		log.Printf("[github_actions] load popular actions: %v", err)
	} else if len(popular) > 0 {
		changed, updated, shaErr := c.checkActionSHAs(ctx, popular)
		if shaErr != nil {
			log.Printf("[github_actions] SHA check error: %v", shaErr)
		} else {
			out = append(out, changed...)
			if saveErr := c.savePopularActions(updated); saveErr != nil {
				log.Printf("[github_actions] save popular actions: %v", saveErr)
			}
		}
	}

	return out, nil
}

// queryOSVAdvisories queries the OSV API for GitHub Actions ecosystem advisories since `since`.
func (c *Client) queryOSVAdvisories(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	body := map[string]any{
		"package": map[string]string{
			"ecosystem": ecosystem,
		},
	}
	if !since.IsZero() {
		body["modified_since"] = since.UTC().Format(time.RFC3339)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvAPIURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned %d", resp.StatusCode)
	}

	var result struct {
		Vulns []struct {
			ID       string   `json:"id"`
			Summary  string   `json:"summary"`
			Details  string   `json:"details"`
			Refs     []struct {
				Type string `json:"type"`
				URL  string `json:"url"`
			} `json:"references"`
			Affected []struct {
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Ranges []struct {
					Type   string `json:"type"`
					Events []struct {
						Introduced string `json:"introduced,omitempty"`
						Fixed       string `json:"fixed,omitempty"`
					} `json:"events"`
				} `json:"ranges"`
				Versions []string `json:"versions"`
			} `json:"affected"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			Modified string `json:"modified"`
		} `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var incidents []*incident.Incident
	for _, v := range result.Vulns {
		inc := osvVulnToIncident(v.ID, v.Summary, v.Details, v.Refs, v.Affected)
		if inc != nil {
			incidents = append(incidents, inc)
		}
	}
	return incidents, nil
}

func osvVulnToIncident(id, summary, details string, refs []struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}, affected []struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced string `json:"introduced,omitempty"`
			Fixed       string `json:"fixed,omitempty"`
		} `json:"events"`
	} `json:"ranges"`
	Versions []string `json:"versions"`
}) *incident.Incident {
	if len(affected) == 0 {
		return nil
	}
	inc := &incident.Incident{
		OSVID:       id,
		AttackType:  "ci_poisoning",
		Severity:    "high",
		Description: summary,
		Source:      "github_actions",
	}
	if details != "" && details != summary {
		inc.Description = details
	}
	for _, r := range refs {
		if r.URL != "" {
			inc.References = append(inc.References, r.URL)
		}
	}
	for _, a := range affected {
		pkg := incident.Package{
			Name:      a.Package.Name,
			Ecosystem: "github-actions",
		}
		pkg.AffectedVersions = append(pkg.AffectedVersions, a.Versions...)
		inc.Packages = append(inc.Packages, pkg)
	}
	if len(inc.Packages) > 0 {
		inc.ID = "github-actions-osv-" + id
	}
	return inc
}

// checkActionSHAs queries GitHub API for the latest tag SHA of each popular action.
// Returns new incidents for unexpected SHA changes plus the updated popular list.
func (c *Client) checkActionSHAs(ctx context.Context, popular []PopularAction) ([]*incident.Incident, []PopularAction, error) {
	var incidents []*incident.Incident
	updated := make([]PopularAction, len(popular))
	copy(updated, popular)

	for i, action := range popular {
		parts := strings.SplitN(action.Name, "/", 2)
		if len(parts) != 2 {
			continue
		}
		owner, repo := parts[0], parts[1]

		sha, err := c.fetchLatestTagSHA(ctx, owner, repo)
		if err != nil {
			log.Printf("[github_actions] SHA fetch %s: %v", action.Name, err)
			continue
		}
		if sha == "" {
			continue
		}

		// First run or SHA unchanged — just record it.
		if action.LastSHA == "" || action.LastSHA == sha {
			updated[i].LastSHA = sha
			continue
		}

		// SHA changed — emit an incident.
		updated[i].LastSHA = sha
		severity := "high"
		if action.Official {
			severity = "critical"
		}
		inc := &incident.Incident{
			ID:          "github-actions-sha-" + strings.ReplaceAll(action.Name, "/", "-"),
			Source:      "github_actions",
			AttackType:  "ci_poisoning",
			Severity:    severity,
			Description: fmt.Sprintf("Unexpected tag SHA change detected for %s: was %s, now %s. This may indicate a tag was moved to point at a different (potentially malicious) commit.", action.Name, action.LastSHA, sha),
			Packages: []incident.Package{
				{Name: action.Name, Ecosystem: "github-actions"},
			},
			References: []string{
				"https://github.com/" + action.Name,
			},
			Indicators: incident.Indicators{
				GitIndicators: &incident.GitIndicators{
					CommitMessages: []string{fmt.Sprintf("unexpected tag SHA change: was %s, now %s", action.LastSHA, sha)},
				},
			},
		}
		incidents = append(incidents, inc)
		log.Printf("[github_actions] SHA change detected for %s: %s -> %s", action.Name, action.LastSHA, sha)
	}

	return incidents, updated, nil
}

// fetchLatestTagSHA returns the commit SHA that the latest tag of owner/repo points to.
// Returns ("", nil) when there are no tags.
func (c *Client) fetchLatestTagSHA(ctx context.Context, owner, repo string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/tags?per_page=1", githubAPI, owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("GitHub API %d: %s", resp.StatusCode, string(body))
	}

	var tags []struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "", err
	}
	if len(tags) == 0 {
		return "", nil
	}
	return tags[0].Commit.SHA, nil
}

func (c *Client) loadPopularActions() ([]PopularAction, error) {
	data, err := os.ReadFile(c.popularPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list popularActionList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list.Actions, nil
}

func (c *Client) savePopularActions(actions []PopularAction) error {
	list := popularActionList{
		Generated: time.Now().UTC(),
		Actions:   actions,
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.popularPath, data, 0o644)
}
