package actor

import (
	"strings"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const (
	minAliasLen        = 6 // ignore aliases shorter than this to avoid false positives
	explicitConfidence = 0.90
	inferredConfidence = 0.65
	// descScanLen previously capped description scanning at 200 chars, which
	// missed actor mentions later in URLhaus/CISA/Sekoia writeups. The audit
	// found 99.9% of incidents had empty actor fields because of this. v0.1.10
	// scans the full description plus references, campaign names, and the
	// ransomware-extension group name. No cap.
)

// Attribute scans each incident for actor name/alias matches against the store,
// writes Campaign.Actor when not set, appends ActorIDs, and updates actor
// profiles with linked incidents and aggregated IOCs. Returns the (mutated)
// incident slice.
func Attribute(incidents []*incident.Incident, store *Store, module string) []*incident.Incident {
	for _, inc := range incidents {
		matches := findMatches(inc, store)
		for slug, matchType := range matches {
			profile, ok := store.profiles[slug]
			if !ok {
				continue
			}

			// Set Campaign.Actor on the incident if not already set.
			if inc.Campaign.Actor == "" {
				inc.Campaign.Actor = profile.Name
			}

			// Reverse link: add actor slug to incident.
			if !contains(inc.ActorIDs, slug) {
				inc.ActorIDs = append(inc.ActorIDs, slug)
			}

			// Forward link: add incident to actor profile (deduplicated).
			if !hasLink(profile, inc.ID) {
				conf := inferredConfidence
				if matchType == "explicit" {
					conf = explicitConfidence
				}
				profile.LinkedIncidents = append(profile.LinkedIncidents, IncidentLink{
					IncidentID: inc.ID,
					Module:     module,
					MatchType:  matchType,
					Confidence: conf,
				})
			}

			// Aggregate IOCs from incident into actor profile.
			aggregateIOCs(profile, inc)
		}
	}
	return incidents
}

// findMatches returns a map of actor slug → match type for all actors matched
// in the given incident. Explicit matches come from Campaign.Actor and
// Campaign.Name; inferred matches come from scanning the title/description.
func findMatches(inc *incident.Incident, store *Store) map[string]string {
	matches := map[string]string{}

	tryMatch := func(name, matchType string) {
		if name == "" {
			return
		}
		if p, ok := store.Lookup(name); ok {
			if existing, alreadySet := matches[p.ID]; !alreadySet || existing == "inferred" {
				matches[p.ID] = matchType
			}
		}
	}

	// Explicit: direct Campaign.Actor / Campaign.Name fields, and the
	// ransomware-extension's group name (ransomware.live publishes a clean
	// `group_name` field that's typically a known alias — LockBit, BlackBasta,
	// etc.).
	tryMatch(inc.Campaign.Actor, "explicit")
	tryMatch(inc.Campaign.Name, "explicit")
	if inc.RansomwareExt != nil {
		tryMatch(inc.RansomwareExt.RansomwareGroup, "explicit")
	}

	// Inferred: scan ID + full description + references + campaign aliases.
	// Pre-v0.1.10 this was id + first 200 chars of description — that missed
	// actor mentions later in writeups (audit: 99.9% of incidents had no
	// actor). References are included because vendor URLs sometimes encode
	// the group name (lockbit-leaks.onion, blackbasta-blog.com, etc.).
	var sb strings.Builder
	sb.WriteString(inc.ID)
	sb.WriteByte(' ')
	sb.WriteString(inc.Description)
	for _, ref := range inc.References {
		sb.WriteByte(' ')
		sb.WriteString(ref)
	}
	combined := strings.ToLower(sb.String())

	for alias, slug := range store.aliases {
		if len(alias) < minAliasLen {
			continue
		}
		if strings.Contains(combined, alias) {
			if _, alreadyExplicit := matches[slug]; !alreadyExplicit {
				matches[slug] = "inferred"
			}
		}
	}

	return matches
}

func aggregateIOCs(profile *ActorProfile, inc *incident.Incident) {
	domainSet := toSet(profile.AggregatedIOCs.Domains)
	for _, d := range inc.Indicators.Domains {
		v := strings.ToLower(d.Value)
		if !domainSet[v] {
			domainSet[v] = true
			profile.AggregatedIOCs.Domains = append(profile.AggregatedIOCs.Domains, v)
		}
	}

	ipSet := toSet(profile.AggregatedIOCs.IPs)
	for _, ip := range inc.Indicators.IPs {
		if !ipSet[ip.Value] {
			ipSet[ip.Value] = true
			profile.AggregatedIOCs.IPs = append(profile.AggregatedIOCs.IPs, ip.Value)
		}
	}

	hashSet := toSet(profile.AggregatedIOCs.Hashes)
	for _, h := range inc.Indicators.FileHashes {
		v := strings.ToLower(h.Value)
		if !hashSet[v] {
			hashSet[v] = true
			profile.AggregatedIOCs.Hashes = append(profile.AggregatedIOCs.Hashes, v)
		}
	}
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func hasLink(profile *ActorProfile, incidentID string) bool {
	for _, l := range profile.LinkedIncidents {
		if l.IncidentID == incidentID {
			return true
		}
	}
	return false
}
