package actor

import (
	"strings"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const (
	minAliasLen       = 6   // ignore aliases shorter than this to avoid false positives
	explicitConfidence = 0.90
	inferredConfidence = 0.65
	descScanLen        = 200 // chars of description to scan for actor names
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

	// Explicit: direct Campaign.Actor or Campaign.Name fields.
	tryMatch(inc.Campaign.Actor, "explicit")
	tryMatch(inc.Campaign.Name, "explicit")

	// Inferred: scan title and first N chars of description.
	scanText := inc.Description
	if len(scanText) > descScanLen {
		scanText = scanText[:descScanLen]
	}
	combined := strings.ToLower(inc.ID + " " + scanText)

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
