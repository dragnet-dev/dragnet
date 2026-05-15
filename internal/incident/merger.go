package incident

import (
	"math"
	"strings"
	"time"
)

// Merge combines multiple incidents covering the same event into one.
// Match criteria: same package+ecosystem, date proximity ≤7 days,
// 2+ overlapping IOCs, or campaign name match.
func Merge(incidents []*Incident) (*Incident, error) {
	if len(incidents) == 0 {
		return nil, nil
	}
	if len(incidents) == 1 {
		return incidents[0], nil
	}

	// Group by matching key, then merge each group.
	groups := groupIncidents(incidents)

	if len(groups) == 1 {
		return mergeGroup(groups[0]), nil
	}

	// Multiple independent groups: return the highest-severity one.
	best := mergeGroup(groups[0])
	for _, g := range groups[1:] {
		merged := mergeGroup(g)
		if severityRank(merged.Severity) > severityRank(best.Severity) {
			best = merged
		}
	}
	return best, nil
}

// MergeAll groups and merges all incidents, returning one per independent event.
func MergeAll(incidents []*Incident) []*Incident {
	if len(incidents) == 0 {
		return nil
	}
	groups := groupIncidents(incidents)
	out := make([]*Incident, 0, len(groups))
	for _, g := range groups {
		out = append(out, mergeGroup(g))
	}
	return out
}

func groupIncidents(incidents []*Incident) [][]*Incident {
	used := make([]bool, len(incidents))
	var groups [][]*Incident

	for i := range incidents {
		if used[i] {
			continue
		}
		group := []*Incident{incidents[i]}
		used[i] = true

		// Expand until stable: keep scanning for any unmatched incident that
		// matches any current group member (not just the seed), so transitivity
		// is preserved (A↔B, B↔C ⟹ {A,B,C} in one group).
		for changed := true; changed; {
			changed = false
			for j := i + 1; j < len(incidents); j++ {
				if used[j] {
					continue
				}
				for _, gm := range group {
					if shouldMerge(gm, incidents[j]) {
						group = append(group, incidents[j])
						used[j] = true
						changed = true
						break
					}
				}
			}
		}
		groups = append(groups, group)
	}
	return groups
}

// trustedSources are high-signal blog parsers whose incidents can merge on a
// single overlapping IOC rather than requiring two.
var trustedSources = map[string]bool{
	"wiz": true, "socket": true, "aikido": true, "stepsecurity": true,
}

// shouldMerge returns true when two incidents cover the same real-world event.
func shouldMerge(a, b *Incident) bool {
	// 1. Package name + ecosystem overlap
	if packageOverlap(a, b) {
		return true
	}

	// 2. Campaign name match
	if a.Campaign.Name != "" && b.Campaign.Name != "" {
		if strings.EqualFold(a.Campaign.Name, b.Campaign.Name) {
			return true
		}
	}

	// 3. Date proximity (≤7 days) + IOC overlap
	// Trusted-source pairs need only 1 overlapping IOC; others need 2.
	if withinDays(a, b, 7) {
		threshold := 2
		if trustedSources[a.Source] && trustedSources[b.Source] {
			threshold = 1
		}
		if iocOverlapCount(a, b) >= threshold {
			return true
		}
	}

	return false
}

func packageOverlap(a, b *Incident) bool {
	for _, pa := range a.Packages {
		for _, pb := range b.Packages {
			if strings.EqualFold(pa.Name, pb.Name) &&
				strings.EqualFold(pa.Ecosystem, pb.Ecosystem) {
				return true
			}
		}
	}
	return false
}

func withinDays(a, b *Incident, days int) bool {
	ta := parseWindowTime(a)
	tb := parseWindowTime(b)
	if ta.IsZero() || tb.IsZero() {
		return false
	}
	diff := ta.Sub(tb)
	if diff < 0 {
		diff = -diff
	}
	return diff <= time.Duration(days)*24*time.Hour
}

func parseWindowTime(inc *Incident) time.Time {
	if inc.CompromiseWindow.Start != "" {
		t, err := time.Parse(time.RFC3339, inc.CompromiseWindow.Start)
		if err == nil {
			return t
		}
	}
	return time.Time{}
}

func iocOverlapCount(a, b *Incident) int {
	count := 0

	// Domain overlap
	domainSet := map[string]bool{}
	for _, d := range a.Indicators.Domains {
		domainSet[strings.ToLower(d.Value)] = true
	}
	for _, d := range b.Indicators.Domains {
		if domainSet[strings.ToLower(d.Value)] {
			count++
		}
	}

	// IP overlap
	ipSet := map[string]bool{}
	for _, ip := range a.Indicators.IPs {
		ipSet[ip.Value] = true
	}
	for _, ip := range b.Indicators.IPs {
		if ipSet[ip.Value] {
			count++
		}
	}

	// Hash overlap
	hashSet := map[string]bool{}
	for _, h := range a.Indicators.FileHashes {
		hashSet[strings.ToLower(h.Value)] = true
	}
	for _, h := range b.Indicators.FileHashes {
		if hashSet[strings.ToLower(h.Value)] {
			count++
		}
	}

	// URL overlap — blog parsers often share the same C2/payload URLs without
	// extracting discrete domains, so count these too.
	urlSet := map[string]bool{}
	for _, u := range a.Indicators.URLs {
		urlSet[strings.ToLower(u.Value)] = true
	}
	for _, u := range b.Indicators.URLs {
		if urlSet[strings.ToLower(u.Value)] {
			count++
		}
	}

	return count
}

// mergeGroup merges all incidents in a group into a single canonical incident.
func mergeGroup(group []*Incident) *Incident {
	if len(group) == 1 {
		return group[0]
	}

	base := *group[0] // shallow copy of first
	base.Packages = unionPackages(group)
	base.References = unionStrings(collectReferences(group))
	base.Severity = highestSeverity(group)
	base.Description = longestDescription(group)

	// Collect all contributing sources into Sources; keep Source as primary.
	var allSources []string
	for _, inc := range group {
		if inc.Source != "" {
			allSources = append(allSources, inc.Source)
		}
		allSources = append(allSources, inc.Sources...)
	}
	base.Sources = unionStrings(allSources)

	// Use the most complete ID/OSV/GHSA
	for _, inc := range group[1:] {
		if base.OSVID == "" && inc.OSVID != "" {
			base.OSVID = inc.OSVID
		}
		if base.GHSAID == "" && inc.GHSAID != "" {
			base.GHSAID = inc.GHSAID
		}
		if base.Campaign.Name == "" && inc.Campaign.Name != "" {
			base.Campaign = inc.Campaign
		}
	}

	base.Indicators = mergeIndicators(group)

	return &base
}

func unionPackages(group []*Incident) []Package {
	seen := map[string]bool{}
	var out []Package
	for _, inc := range group {
		for _, pkg := range inc.Packages {
			key := strings.ToLower(pkg.Ecosystem + "|" + pkg.Name)
			if !seen[key] {
				seen[key] = true
				out = append(out, pkg)
			}
		}
	}
	return out
}

func collectReferences(group []*Incident) []string {
	var all []string
	for _, inc := range group {
		all = append(all, inc.References...)
	}
	return all
}

func unionStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func highestSeverity(group []*Incident) string {
	best := 0
	for _, inc := range group {
		if r := severityRank(inc.Severity); r > best {
			best = r
		}
	}
	return severityFromRank(best)
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func severityFromRank(r int) string {
	switch r {
	case 4:
		return "critical"
	case 3:
		return "high"
	case 2:
		return "medium"
	case 1:
		return "low"
	default:
		return "medium"
	}
}

func longestDescription(group []*Incident) string {
	best := ""
	for _, inc := range group {
		if len(inc.Description) > len(best) {
			best = inc.Description
		}
	}
	return best
}

func mergeIndicators(group []*Incident) Indicators {
	var out Indicators

	// Domains
	domainMap := map[string]*IndicatorValue{}
	for _, inc := range group {
		for _, d := range inc.Indicators.Domains {
			key := strings.ToLower(d.Value)
			if existing, ok := domainMap[key]; ok {
				existing.Sources = unionStrings(append(existing.Sources, d.Sources...))
				existing.Confidence = math.Min(calculateConfidence(existing.Sources), 0.98)
			} else {
				cp := d
				domainMap[key] = &cp
			}
		}
	}
	for _, v := range domainMap {
		out.Domains = append(out.Domains, *v)
	}

	// IPs
	ipMap := map[string]*IndicatorValue{}
	for _, inc := range group {
		for _, ip := range inc.Indicators.IPs {
			if existing, ok := ipMap[ip.Value]; ok {
				existing.Sources = unionStrings(append(existing.Sources, ip.Sources...))
				existing.Confidence = math.Min(calculateConfidence(existing.Sources), 0.98)
			} else {
				cp := ip
				ipMap[ip.Value] = &cp
			}
		}
	}
	for _, v := range ipMap {
		out.IPs = append(out.IPs, *v)
	}

	// File hashes
	hashMap := map[string]*FileHash{}
	for _, inc := range group {
		for _, h := range inc.Indicators.FileHashes {
			key := strings.ToLower(h.Algorithm + "|" + h.Value)
			if existing, ok := hashMap[key]; ok {
				existing.Sources = unionStrings(append(existing.Sources, h.Sources...))
				existing.Confidence = math.Min(calculateConfidence(existing.Sources), 0.98)
			} else {
				cp := h
				hashMap[key] = &cp
			}
		}
	}
	for _, v := range hashMap {
		out.FileHashes = append(out.FileHashes, *v)
	}

	// URLs
	urlMap := map[string]*IndicatorValue{}
	for _, inc := range group {
		for _, u := range inc.Indicators.URLs {
			key := strings.ToLower(u.Value)
			if existing, ok := urlMap[key]; ok {
				existing.Sources = unionStrings(append(existing.Sources, u.Sources...))
				existing.Confidence = math.Min(calculateConfidence(existing.Sources), 0.98)
			} else {
				cp := u
				urlMap[key] = &cp
			}
		}
	}
	for _, v := range urlMap {
		out.URLs = append(out.URLs, *v)
	}

	// File names (union)
	out.FileNames = unionStrings(collectFileNames(group))

	// File paths (union)
	out.FilePaths = unionStrings(collectFilePaths(group))

	// Persistence (merge all)
	for _, inc := range group {
		if inc.Indicators.Persistence != nil {
			if out.Persistence == nil {
				out.Persistence = &Persistence{}
			}
			out.Persistence.ServiceNames = unionStrings(append(out.Persistence.ServiceNames, inc.Indicators.Persistence.ServiceNames...))
			out.Persistence.MacOSLaunchAgent = unionStrings(append(out.Persistence.MacOSLaunchAgent, inc.Indicators.Persistence.MacOSLaunchAgent...))
			out.Persistence.LinuxSystemd = unionStrings(append(out.Persistence.LinuxSystemd, inc.Indicators.Persistence.LinuxSystemd...))
		}
	}

	// SessionNetwork: keep first non-nil, union SeedNodes
	for _, inc := range group {
		if inc.Indicators.SessionNetwork != nil {
			if out.SessionNetwork == nil {
				cp := *inc.Indicators.SessionNetwork
				out.SessionNetwork = &cp
			} else {
				out.SessionNetwork.SeedNodes = unionStrings(append(out.SessionNetwork.SeedNodes, inc.Indicators.SessionNetwork.SeedNodes...))
				if out.SessionNetwork.RecipientID == "" {
					out.SessionNetwork.RecipientID = inc.Indicators.SessionNetwork.RecipientID
				}
				if out.SessionNetwork.FileServer == "" {
					out.SessionNetwork.FileServer = inc.Indicators.SessionNetwork.FileServer
				}
			}
		}
	}

	// GitIndicators: union string slices
	for _, inc := range group {
		if inc.Indicators.GitIndicators != nil {
			if out.GitIndicators == nil {
				out.GitIndicators = &GitIndicators{}
			}
			out.GitIndicators.RepoDescriptions = unionStrings(append(out.GitIndicators.RepoDescriptions, inc.Indicators.GitIndicators.RepoDescriptions...))
			out.GitIndicators.CommitMessages = unionStrings(append(out.GitIndicators.CommitMessages, inc.Indicators.GitIndicators.CommitMessages...))
		}
	}

	// CredentialTargets: union string slices
	for _, inc := range group {
		if inc.Indicators.CredentialTargets != nil {
			if out.CredentialTargets == nil {
				out.CredentialTargets = &CredentialTargets{}
			}
			out.CredentialTargets.EnvVars = unionStrings(append(out.CredentialTargets.EnvVars, inc.Indicators.CredentialTargets.EnvVars...))
			out.CredentialTargets.MetadataEndpoints = unionStrings(append(out.CredentialTargets.MetadataEndpoints, inc.Indicators.CredentialTargets.MetadataEndpoints...))
			out.CredentialTargets.VaultTypes = unionStrings(append(out.CredentialTargets.VaultTypes, inc.Indicators.CredentialTargets.VaultTypes...))
		}
	}

	return out
}

func collectFileNames(group []*Incident) []string {
	var all []string
	for _, inc := range group {
		all = append(all, inc.Indicators.FileNames...)
	}
	return all
}

func collectFilePaths(group []*Incident) []string {
	var all []string
	for _, inc := range group {
		all = append(all, inc.Indicators.FilePaths...)
	}
	return all
}

// calculateConfidence is a local copy of the confidence calculation to avoid
// an import cycle. The canonical implementation is in internal/confidence.
func calculateConfidence(sources []string) float64 {
	weights := map[string]float64{
		"osv": 0.95, "ghsa": 0.95, "ossf": 0.85, "cisa": 0.90,
		"wiz": 0.90, "socket": 0.90, "aikido": 0.80, "stepsecurity": 0.80,
	}
	if len(sources) == 0 {
		return 0.30
	}
	max := 0.0
	for _, s := range sources {
		if w := weights[s]; w > max {
			max = w
		}
	}
	bonus := math.Min(float64(len(sources)-1)*0.08, 0.20)
	return math.Min(max+bonus, 0.98)
}
