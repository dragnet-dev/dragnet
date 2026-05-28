package index

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/dragnet-dev/dragnet/internal/schema"
)

// ModuleStats summarises incident and IOC counts for a single module.
type ModuleStats struct {
	Incidents int `json:"incidents"`
	IOCs      int `json:"iocs"`
}

// CampaignSummary groups related incidents by campaign name.
type CampaignSummary struct {
	Name        string   `json:"name"`
	Actor       string   `json:"actor,omitempty"`
	Confidence  string   `json:"confidence,omitempty"`
	IncidentIDs []string `json:"incident_ids"`
	FirstSeen   string   `json:"first_seen,omitempty"`
	LastSeen    string   `json:"last_seen,omitempty"`
	Active      bool     `json:"active"`
}

// ImpactIndexEntry summarises impact data for the index.
type ImpactIndexEntry struct {
	TotalWeeklyDownloads int64  `json:"total_weekly_downloads,omitempty"`
	OverallImpactRating  string `json:"overall_impact_rating,omitempty"`
	TopPackageDownloads  int64  `json:"top_package_downloads,omitempty"`
}

// TyposquatIndexEntry summarises typosquat target data for the index.
type TyposquatIndexEntry struct {
	Package         string `json:"package"`
	WeeklyDownloads int64  `json:"weekly_downloads"`
	ImpactRating    string `json:"impact_rating"`
}

// IncidentSummary is a compact per-incident entry in the module index.
type IncidentSummary struct {
	ID                 string               `json:"id"`
	Packages           []string             `json:"packages,omitempty"`
	Ecosystem          string               `json:"ecosystem,omitempty"`
	Severity           string               `json:"severity"`
	AttackType         string               `json:"attack_type"`
	Campaign           string               `json:"campaign,omitempty"`
	Actor              string               `json:"actor,omitempty"`
	Published          string               `json:"published,omitempty"`
	IOCCount           int                  `json:"ioc_count"`
	SourceCount        int                  `json:"source_count"`
	Sources            []string             `json:"sources,omitempty"`
	CrossDomain        bool                 `json:"cross_domain,omitempty"`
	CrossDomainModules []string             `json:"cross_domain_modules,omitempty"`
	IOCs               []IOCSummary         `json:"iocs,omitempty"`
	Impact             *ImpactIndexEntry    `json:"impact,omitempty"`
	TyposquatTarget    *TyposquatIndexEntry `json:"typosquat_target,omitempty"`
}

// IOCSummary is a brief IOC entry within an IncidentSummary.
type IOCSummary struct {
	Type       string  `json:"type"`
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence,omitempty"`
}

// SchemaVersion is the current haul schema version, sourced from the
// canonical internal/schema package. Kept as a package-level alias so
// callers that import index directly don't need a second import.
const SchemaVersion = schema.Version

// ModuleIndex is the schema for {module}/incidents/index.json.
type ModuleIndex struct {
	SchemaVersion string            `json:"$schema_version"`
	Generated     string            `json:"generated"`
	Module        string            `json:"module"`
	Stats         ModuleIndexStats  `json:"stats"`
	Campaigns     []CampaignSummary `json:"campaigns,omitempty"`
	Incidents     []IncidentSummary `json:"incidents"`
}

// ModuleIndexStats holds aggregate numbers for a module index.
type ModuleIndexStats struct {
	TotalIncidents int    `json:"total_incidents"`
	TotalIOCs      int    `json:"total_iocs"`
	LastSync       string `json:"last_sync"`
}

// CrossDomainIncident describes an IOC or actor shared across modules.
type CrossDomainIncident struct {
	Modules     []string `json:"modules"`
	SharedIOC   string   `json:"shared_ioc,omitempty"`
	Actor       string   `json:"actor,omitempty"`
	IncidentIDs []string `json:"incident_ids"`
	Confidence  float64  `json:"confidence"`
}

// RecentEntry is a brief entry in the root index recent list.
type RecentEntry struct {
	Module      string `json:"module"`
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Summary     string `json:"summary"`
	Published   string `json:"published,omitempty"`
	CrossDomain bool   `json:"cross_domain,omitempty"`
}

// RootIndex is the schema for incidents/index.json.
type RootIndex struct {
	SchemaVersion        string                 `json:"$schema_version"`
	Generated            string                 `json:"generated"`
	Stats                map[string]ModuleStats `json:"stats"`
	CrossDomainIncidents []CrossDomainIncident  `json:"cross_domain_incidents,omitempty"`
	Recent               []RecentEntry          `json:"recent,omitempty"`
}

// GenerateModuleIndex writes {outputDir}/incidents/index.json for a single module.
func GenerateModuleIndex(module string, incidents []*incident.Incident, outputDir string) error {
	now := time.Now().UTC().Format(time.RFC3339)

	idx := ModuleIndex{
		SchemaVersion: SchemaVersion,
		Generated:     now,
		Module:        module,
		Stats: ModuleIndexStats{
			TotalIncidents: len(incidents),
			TotalIOCs:      countIOCs(incidents),
			LastSync:       now,
		},
		Campaigns: buildCampaigns(incidents),
		Incidents: buildIncidentSummaries(incidents),
	}

	dest := filepath.Join(outputDir, "incidents", "v1", "index.json")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return err
	}
	ensureSymlink(
		filepath.Join(outputDir, "incidents", "index.json"),
		filepath.Join("v1", "index.json"),
	)
	return nil
}

// GenerateRootIndex writes incidents/index.json aggregating all modules.
func GenerateRootIndex(allModules map[string][]*incident.Incident, rootDir string) error {
	now := time.Now().UTC().Format(time.RFC3339)

	stats := map[string]ModuleStats{}
	var allIncidents []*incident.Incident
	total := ModuleStats{}

	for module, incidents := range allModules {
		iocs := countIOCs(incidents)
		stats[module] = ModuleStats{Incidents: len(incidents), IOCs: iocs}
		total.Incidents += len(incidents)
		total.IOCs += iocs
		allIncidents = append(allIncidents, incidents...)
	}
	stats["total"] = total

	idx := RootIndex{
		SchemaVersion:        SchemaVersion,
		Generated:            now,
		Stats:                stats,
		CrossDomainIncidents: buildCrossDomainIncidents(allModules),
		Recent:               buildRecent(allModules, 20),
	}

	_ = allIncidents // used via allModules above

	dest := filepath.Join(rootDir, "incidents", "v1", "index.json")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return err
	}
	ensureSymlink(
		filepath.Join(rootDir, "incidents", "index.json"),
		filepath.Join("v1", "index.json"),
	)
	return nil
}

func countIOCs(incidents []*incident.Incident) int {
	n := 0
	for _, inc := range incidents {
		n += len(inc.Indicators.Domains)
		n += len(inc.Indicators.IPs)
		n += len(inc.Indicators.URLs)
		n += len(inc.Indicators.FileHashes)
	}
	return n
}

func buildCampaigns(incidents []*incident.Incident) []CampaignSummary {
	type camp struct {
		Actor      string
		Confidence string
		IDs        []string
	}
	byName := map[string]*camp{}

	for _, inc := range incidents {
		name := inc.Campaign.Name
		if name == "" {
			continue
		}
		c, ok := byName[name]
		if !ok {
			c = &camp{Actor: inc.Campaign.Actor, Confidence: inc.Campaign.Confidence}
			byName[name] = c
		}
		c.IDs = append(c.IDs, inc.ID)
	}

	var out []CampaignSummary
	for name, c := range byName {
		out = append(out, CampaignSummary{
			Name:        name,
			Actor:       c.Actor,
			Confidence:  c.Confidence,
			IncidentIDs: c.IDs,
			Active:      true,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func buildIncidentSummaries(incidents []*incident.Incident) []IncidentSummary {
	out := make([]IncidentSummary, 0, len(incidents))
	for _, inc := range incidents {
		var pkgNames []string
		var ecosystem string
		var allSources []string
		seen := map[string]bool{}
		addSrc := func(s string) {
			if s != "" && !seen[s] {
				seen[s] = true
				allSources = append(allSources, s)
			}
		}
		for _, pkg := range inc.Packages {
			pkgNames = append(pkgNames, pkg.Name)
			if ecosystem == "" {
				ecosystem = pkg.Ecosystem
			}
		}
		// Source attribution — collect from every place a source name can
		// live. Pre-v0.1.10 this only read inc.Indicators.Domains[].Sources,
		// so any record without domain IOCs (NVD/CISA/Trivy → 99% of cve +
		// container) reported source_count: 0 in the index even though
		// inc.Source / inc.Sources were populated.
		addSrc(inc.Source)
		for _, s := range inc.Sources {
			addSrc(s)
		}
		for _, d := range inc.Indicators.Domains {
			for _, s := range d.Sources {
				addSrc(s)
			}
		}

		iocs := iocSummaries(inc)

		s := IncidentSummary{
			ID:                 inc.ID,
			Packages:           pkgNames,
			Ecosystem:          ecosystem,
			Severity:           inc.Severity,
			AttackType:         inc.AttackType,
			Campaign:           inc.Campaign.Name,
			Actor:              inc.Campaign.Actor,
			// Populate from compromise_window.start — without this, port's
			// listing UI hides every timestamp because the field is empty.
			Published:          inc.CompromiseWindow.Start,
			IOCCount:           countIOCs([]*incident.Incident{inc}),
			SourceCount:        len(allSources),
			Sources:            allSources,
			CrossDomain:        len(inc.CrossDomainSources) > 0,
			CrossDomainModules: inc.CrossDomainSources,
			IOCs:               iocs,
			Impact:             buildImpactEntry(inc),
			TyposquatTarget:    buildTyposquatEntry(inc),
		}
		out = append(out, s)
	}
	return out
}

func iocSummaries(inc *incident.Incident) []IOCSummary {
	var out []IOCSummary
	for _, d := range inc.Indicators.Domains {
		out = append(out, IOCSummary{Type: "domain", Value: d.Value, Confidence: d.Confidence})
	}
	for _, ip := range inc.Indicators.IPs {
		out = append(out, IOCSummary{Type: "ip", Value: ip.Value, Confidence: ip.Confidence})
	}
	for _, h := range inc.Indicators.FileHashes {
		out = append(out, IOCSummary{Type: h.Algorithm, Value: h.Value, Confidence: h.Confidence})
	}
	return out
}

func buildCrossDomainIncidents(allModules map[string][]*incident.Incident) []CrossDomainIncident {
	var out []CrossDomainIncident
	seen := map[string]bool{}

	for _, incidents := range allModules {
		for _, inc := range incidents {
			for _, link := range inc.CrossDomainLinks {
				var key string
				if link.SharedIOC != nil {
					key = link.SharedIOC.Value + "|" + inc.ID + "|" + link.IncidentID
				} else {
					key = link.Actor + "|" + inc.ID + "|" + link.IncidentID
				}
				if seen[key] {
					continue
				}
				seen[key] = true

				cdi := CrossDomainIncident{
					Modules:     []string{incidentModule(inc.ID), link.Module},
					IncidentIDs: []string{inc.ID, link.IncidentID},
					Confidence:  link.Confidence,
				}
				if link.SharedIOC != nil {
					cdi.SharedIOC = link.SharedIOC.Value
				}
				if link.Actor != "" {
					cdi.Actor = link.Actor
				}
				out = append(out, cdi)
			}
		}
	}
	return out
}

// incidentModule guesses the module from an incident ID prefix.
func incidentModule(id string) string {
	switch {
	case len(id) >= 3 && (id[:3] == "npm" || id[:4] == "pypi" || id[:5] == "cargo"):
		return "supply"
	case len(id) >= 3 && id[:3] == "mal":
		return "malware"
	case len(id) >= 3 && id[:3] == "ran":
		return "ransomware"
	case len(id) >= 3 && id[:3] == "cve":
		return "cve"
	default:
		return "supply"
	}
}

func buildImpactEntry(inc *incident.Incident) *ImpactIndexEntry {
	if inc.Impact == nil {
		return nil
	}
	entry := &ImpactIndexEntry{
		TotalWeeklyDownloads: inc.Impact.TotalWeeklyDownloads,
		OverallImpactRating:  inc.Impact.OverallImpactRating,
	}
	for _, p := range inc.Impact.Packages {
		if p.WeeklyDownloads > entry.TopPackageDownloads {
			entry.TopPackageDownloads = p.WeeklyDownloads
		}
	}
	return entry
}

func buildTyposquatEntry(inc *incident.Incident) *TyposquatIndexEntry {
	if inc.TyposquatInfo == nil {
		return nil
	}
	return &TyposquatIndexEntry{
		Package:         inc.TyposquatInfo.TargetPackage,
		WeeklyDownloads: inc.TyposquatInfo.TargetWeeklyDownloads,
		ImpactRating:    inc.TyposquatInfo.TargetImpactRating,
	}
}

func buildRecent(allModules map[string][]*incident.Incident, n int) []RecentEntry {
	var all []RecentEntry
	for module, incidents := range allModules {
		for _, inc := range incidents {
			summary := inc.Campaign.Name
			if summary == "" {
				summary = inc.Description
				if len(summary) > 80 {
					summary = summary[:80] + "..."
				}
			}
			all = append(all, RecentEntry{
				Module:      module,
				ID:          inc.ID,
				Severity:    inc.Severity,
				Summary:     summary,
				CrossDomain: len(inc.CrossDomainSources) > 0,
			})
		}
	}

	// Most recently added incidents first (use slice order as-is, no timestamps)
	if len(all) > n {
		all = all[:n]
	}
	return all
}
