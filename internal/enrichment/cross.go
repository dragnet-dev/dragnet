package enrichment

import (
	"math"

	"github.com/dragnet-dev/dragnet/internal/config"
	"github.com/dragnet-dev/dragnet/internal/incident"
)

// CrossEnricher boosts IOC confidence when the same indicator appears across
// multiple Dragnet modules, and links incidents that share actors or infrastructure.
type CrossEnricher struct {
	cfg config.CrossEnrichConfig
}

// New returns a CrossEnricher configured from cfg.
func New(cfg config.CrossEnrichConfig) *CrossEnricher {
	return &CrossEnricher{cfg: cfg}
}

type iocAppearance struct {
	Module   string
	Incident *incident.Incident
	IOCValue string
}

// Enrich mutates incidents in allModules in-place.
// allModules maps module name → slice of incidents for that module.
func (e *CrossEnricher) Enrich(allModules map[string][]*incident.Incident) {
	if !e.cfg.Enabled {
		return
	}

	// OS packages ↔ container cross-domain linking via shared CVE IDs.
	if len(allModules["os-packages"]) > 0 && len(allModules["container"]) > 0 {
		LinkOSToContainer(allModules["os-packages"], allModules["container"])
	}

	// Build IOC index: value → list of (module, incident)
	iocIndex := map[string][]iocAppearance{}
	for module, incidents := range allModules {
		for _, inc := range incidents {
			for _, d := range inc.Indicators.Domains {
				iocIndex[d.Value] = append(iocIndex[d.Value], iocAppearance{module, inc, d.Value})
			}
			for _, ip := range inc.Indicators.IPs {
				iocIndex[ip.Value] = append(iocIndex[ip.Value], iocAppearance{module, inc, ip.Value})
			}
			for _, h := range inc.Indicators.FileHashes {
				iocIndex[h.Value] = append(iocIndex[h.Value], iocAppearance{module, inc, h.Value})
			}
		}
	}

	// Apply confidence boosts for IOCs appearing in 2+ modules
	for _, appearances := range iocIndex {
		if len(appearances) < 2 {
			continue
		}
		// Count distinct modules
		seenModules := map[string]bool{}
		for _, a := range appearances {
			seenModules[a.Module] = true
		}
		if len(seenModules) < 2 {
			continue
		}
		boost := float64(len(seenModules)-1) * e.cfg.ConfidenceBoostPerDomain

		distinctModules := make([]string, 0, len(seenModules))
		for m := range seenModules {
			distinctModules = append(distinctModules, m)
		}

		for _, app := range appearances {
			boostDomains(app.Incident, app.IOCValue, boost)
			boostIPs(app.Incident, app.IOCValue, boost)
			boostHashes(app.Incident, app.IOCValue, boost)
			for _, m := range distinctModules {
				app.Incident.CrossDomainSources = uniqueAppend(app.Incident.CrossDomainSources, m)
			}
		}
	}

	// Link shared actors
	if e.cfg.LinkSharedActors {
		e.linkSharedActors(allModules)
	}

	// Link shared infrastructure
	if e.cfg.LinkSharedInfrastructure {
		e.linkSharedInfrastructure(allModules, iocIndex)
	}
}

func boostDomains(inc *incident.Incident, value string, boost float64) {
	for i, d := range inc.Indicators.Domains {
		if d.Value == value {
			inc.Indicators.Domains[i].Confidence = math.Min(d.Confidence+boost, 0.98)
		}
	}
}

func boostIPs(inc *incident.Incident, value string, boost float64) {
	for i, ip := range inc.Indicators.IPs {
		if ip.Value == value {
			inc.Indicators.IPs[i].Confidence = math.Min(ip.Confidence+boost, 0.98)
		}
	}
}

func boostHashes(inc *incident.Incident, value string, boost float64) {
	for i, h := range inc.Indicators.FileHashes {
		if h.Value == value {
			inc.Indicators.FileHashes[i].Confidence = math.Min(h.Confidence+boost, 0.98)
		}
	}
}

func (e *CrossEnricher) linkSharedActors(allModules map[string][]*incident.Incident) {
	// Build actor → list of (module, incident)
	type actorEntry struct {
		Module   string
		Incident *incident.Incident
	}
	actorIndex := map[string][]actorEntry{}
	for module, incidents := range allModules {
		for _, inc := range incidents {
			if inc.Campaign.Actor != "" {
				actorIndex[inc.Campaign.Actor] = append(actorIndex[inc.Campaign.Actor],
					actorEntry{module, inc})
			}
		}
	}

	for actor, entries := range actorIndex {
		if len(entries) < 2 {
			continue
		}
		// Check they span multiple modules
		seenModules := map[string]bool{}
		for _, e := range entries {
			seenModules[e.Module] = true
		}
		if len(seenModules) < 2 {
			continue
		}

		for _, entry := range entries {
			// Build existing link set to skip duplicates without O(N) scans.
			existing := make(map[string]struct{}, len(entry.Incident.CrossDomainLinks))
			for _, l := range entry.Incident.CrossDomainLinks {
				existing[l.Module+"\x00"+l.IncidentID+"\x00"+l.Relationship] = struct{}{}
			}
			for _, other := range entries {
				if other.Incident == entry.Incident {
					continue
				}
				key := other.Module + "\x00" + other.Incident.ID + "\x00same_actor"
				if _, dup := existing[key]; dup {
					continue
				}
				existing[key] = struct{}{}
				entry.Incident.CrossDomainLinks = append(entry.Incident.CrossDomainLinks,
					incident.CrossDomainLink{
						Module:       other.Module,
						IncidentID:   other.Incident.ID,
						Relationship: "same_actor",
						Actor:        actor,
						Confidence:   bestActorConfidence(entry.Incident, other.Incident),
					},
				)
			}
		}
	}
}

func (e *CrossEnricher) linkSharedInfrastructure(allModules map[string][]*incident.Incident, iocIndex map[string][]iocAppearance) {
	// Pre-build per-incident IOC type index to avoid O(indicators) scan inside inner loop.
	iocTypeCache := make(map[*incident.Incident]map[string]string)
	for _, appearances := range iocIndex {
		for _, app := range appearances {
			if iocTypeCache[app.Incident] == nil {
				iocTypeCache[app.Incident] = buildIOCTypeIndex(app.Incident)
			}
		}
	}

	for iocVal, appearances := range iocIndex {
		seenModules := map[string]bool{}
		for _, a := range appearances {
			seenModules[a.Module] = true
		}
		if len(seenModules) < 2 {
			continue
		}

		for _, app := range appearances {
			iocType := iocTypeCache[app.Incident][iocVal]
			// Build existing link set to skip duplicates without O(N) scans.
			existing := make(map[string]struct{}, len(app.Incident.CrossDomainLinks))
			for _, l := range app.Incident.CrossDomainLinks {
				existing[l.Module+"\x00"+l.IncidentID+"\x00"+l.Relationship] = struct{}{}
			}
			for _, other := range appearances {
				if other.Incident == app.Incident {
					continue
				}
				key := other.Module + "\x00" + other.Incident.ID + "\x00shared_infrastructure"
				if _, dup := existing[key]; dup {
					continue
				}
				existing[key] = struct{}{}
				app.Incident.CrossDomainLinks = append(app.Incident.CrossDomainLinks,
					incident.CrossDomainLink{
						Module:       other.Module,
						IncidentID:   other.Incident.ID,
						Relationship: "shared_infrastructure",
						SharedIOC: &incident.SharedIOC{
							Type:  iocType,
							Value: iocVal,
						},
						Confidence: bestIOCConfidence(app.Incident, iocVal),
					},
				)
			}
		}
	}
}

// iocTypeOfValue returns "domain", "ip", or "hash" for a given IOC value in an incident.
func iocTypeOfValue(inc *incident.Incident, value string) string {
	for _, d := range inc.Indicators.Domains {
		if d.Value == value {
			return "domain"
		}
	}
	for _, ip := range inc.Indicators.IPs {
		if ip.Value == value {
			return "ip"
		}
	}
	return "hash"
}

// buildIOCTypeIndex builds a map of IOC value → type for a single incident,
// used to avoid repeated linear scans inside the infrastructure linking loop.
func buildIOCTypeIndex(inc *incident.Incident) map[string]string {
	total := len(inc.Indicators.Domains) + len(inc.Indicators.IPs) + len(inc.Indicators.FileHashes)
	m := make(map[string]string, total)
	for _, d := range inc.Indicators.Domains {
		m[d.Value] = "domain"
	}
	for _, ip := range inc.Indicators.IPs {
		m[ip.Value] = "ip"
	}
	for _, h := range inc.Indicators.FileHashes {
		if _, exists := m[h.Value]; !exists {
			m[h.Value] = "hash"
		}
	}
	return m
}

func bestActorConfidence(a, b *incident.Incident) float64 {
	confA := campaignConfidenceFloat(a.Campaign.Confidence)
	confB := campaignConfidenceFloat(b.Campaign.Confidence)
	if confA > confB {
		return confA
	}
	return confB
}

func campaignConfidenceFloat(s string) float64 {
	switch s {
	case "high":
		return 0.90
	case "medium":
		return 0.70
	case "low":
		return 0.40
	default:
		return 0.60
	}
}

func bestIOCConfidence(inc *incident.Incident, value string) float64 {
	best := 0.0
	for _, d := range inc.Indicators.Domains {
		if d.Value == value && d.Confidence > best {
			best = d.Confidence
		}
	}
	for _, ip := range inc.Indicators.IPs {
		if ip.Value == value && ip.Confidence > best {
			best = ip.Confidence
		}
	}
	for _, h := range inc.Indicators.FileHashes {
		if h.Value == value && h.Confidence > best {
			best = h.Confidence
		}
	}
	return best
}

func uniqueAppend(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func appendLinkOnce(links []incident.CrossDomainLink, link incident.CrossDomainLink) []incident.CrossDomainLink {
	for _, l := range links {
		if l.Module == link.Module && l.IncidentID == link.IncidentID && l.Relationship == link.Relationship {
			return links
		}
	}
	return append(links, link)
}
