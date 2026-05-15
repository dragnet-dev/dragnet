package mitre

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/actor"
)

const attackURL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

// Client fetches the MITRE ATT&CK enterprise bundle.
type Client struct {
	http *http.Client
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: 60 * time.Second}}
}

// FetchActors downloads the ATT&CK STIX bundle and returns actor profiles.
// If lastETag matches the server's ETag, profiles is nil (no change).
// Returns (profiles, newETag, error).
func (c *Client) FetchActors(ctx context.Context, lastETag string) ([]*actor.ActorProfile, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, attackURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Dragnet-CTI-Bot/1.0")
	if lastETag != "" {
		req.Header.Set("If-None-Match", lastETag)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("mitre: %w", err)
	}
	defer resp.Body.Close()

	newETag := resp.Header.Get("ETag")

	if resp.StatusCode == http.StatusNotModified {
		return nil, newETag, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("mitre: HTTP %d", resp.StatusCode)
	}

	var bundle attackBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, "", fmt.Errorf("mitre decode: %w", err)
	}

	profiles := parseBundle(&bundle)
	return profiles, newETag, nil
}

// ── ATT&CK STIX bundle types ──────────────────────────────────────────────

type attackBundle struct {
	Objects []json.RawMessage `json:"objects"`
}

type stixCommon struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type intrusionSet struct {
	stixCommon
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	Aliases          []string `json:"aliases"`
	XMitreAliases    []string `json:"x_mitre_aliases"`
	ExternalRefs     []extRef `json:"external_references"`
	FirstSeen        string   `json:"first_seen"`
	LastSeen         string   `json:"last_seen"`
	XMitreDeprecated bool     `json:"x_mitre_deprecated"`
	Revoked          bool     `json:"revoked"`
}

type attackPattern struct {
	stixCommon
	Name         string   `json:"name"`
	ExternalRefs []extRef `json:"external_references"`
}

type relationship struct {
	stixCommon
	RelationshipType string `json:"relationship_type"`
	SourceRef        string `json:"source_ref"`
	TargetRef        string `json:"target_ref"`
}

type toolOrMalware struct {
	stixCommon
	Name string `json:"name"`
}

type extRef struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
}

// ── Parsing ───────────────────────────────────────────────────────────────

func parseBundle(bundle *attackBundle) []*actor.ActorProfile {
	// First pass: index all object types.
	var groups []intrusionSet
	patterns := map[string]attackPattern{} // stix-id → pattern
	tools := map[string]string{}           // stix-id → name
	var rels []relationship

	for _, raw := range bundle.Objects {
		var base stixCommon
		if err := json.Unmarshal(raw, &base); err != nil {
			continue
		}
		switch base.Type {
		case "intrusion-set":
			var g intrusionSet
			if err := json.Unmarshal(raw, &g); err == nil && !g.XMitreDeprecated && !g.Revoked {
				groups = append(groups, g)
			}
		case "attack-pattern":
			var p attackPattern
			if err := json.Unmarshal(raw, &p); err == nil {
				patterns[p.ID] = p
			}
		case "tool", "malware":
			var t toolOrMalware
			if err := json.Unmarshal(raw, &t); err == nil {
				tools[t.ID] = t.Name
			}
		case "relationship":
			var r relationship
			if err := json.Unmarshal(raw, &r); err == nil {
				rels = append(rels, r)
			}
		}
	}

	// Build group slug → profile map.
	profileByStixID := make(map[string]*actor.ActorProfile, len(groups))
	for i := range groups {
		g := &groups[i]
		profile := groupToProfile(g)
		profileByStixID[g.ID] = profile
	}

	// Second pass: wire TTPs and software via relationships.
	for _, r := range rels {
		if r.RelationshipType != "uses" {
			continue
		}
		profile, ok := profileByStixID[r.SourceRef]
		if !ok {
			continue
		}
		if pat, ok := patterns[r.TargetRef]; ok {
			tid := mitreID(pat.ExternalRefs)
			if tid != "" && !hasTTP(profile, tid) {
				profile.TTPs = append(profile.TTPs, actor.TTP{ID: tid, Name: pat.Name})
			}
		} else if name, ok := tools[r.TargetRef]; ok {
			if !contains(profile.Software, name) {
				profile.Software = append(profile.Software, name)
			}
		}
	}

	profiles := make([]*actor.ActorProfile, 0, len(profileByStixID))
	for _, p := range profileByStixID {
		profiles = append(profiles, p)
	}
	return profiles
}

func groupToProfile(g *intrusionSet) *actor.ActorProfile {
	slug := slugify(g.Name)
	aliases := dedupeStrings(append(g.XMitreAliases, g.Aliases...))
	// Remove the canonical name from the alias list.
	var filteredAliases []string
	for _, a := range aliases {
		if !strings.EqualFold(a, g.Name) {
			filteredAliases = append(filteredAliases, a)
		}
	}

	return &actor.ActorProfile{
		ID:          slug,
		Name:        g.Name,
		MITREID:     mitreID(g.ExternalRefs),
		Aliases:     filteredAliases,
		Type:        inferActorType(g.Description),
		Description: truncate(g.Description, 500),
		FirstSeen:   g.FirstSeen,
		LastSeen:    g.LastSeen,
		Confidence:  "high",
	}
}

var reNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(name string) string {
	s := strings.ToLower(name)
	s = reNonAlnum.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	return s
}

func mitreID(refs []extRef) string {
	for _, r := range refs {
		if r.SourceName == "mitre-attack" {
			return r.ExternalID
		}
	}
	return ""
}

func inferActorType(desc string) string {
	d := strings.ToLower(desc)
	switch {
	case strings.Contains(d, "nation-state") || strings.Contains(d, "state-sponsored") ||
		strings.Contains(d, "government") || strings.Contains(d, "military intelligence"):
		return "nation-state"
	case strings.Contains(d, "financially motivated") || strings.Contains(d, "ransomware") ||
		strings.Contains(d, "criminal") || strings.Contains(d, "cybercrime"):
		return "criminal"
	case strings.Contains(d, "hacktivist") || strings.Contains(d, "ideology"):
		return "hacktivist"
	default:
		return "unknown"
	}
}

func hasTTP(profile *actor.ActorProfile, id string) bool {
	for _, t := range profile.TTPs {
		if t.ID == id {
			return true
		}
	}
	return false
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func dedupeStrings(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
