package incident

import (
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/confidence"
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
//
// Algorithm: union-find by every merge key (every package, every campaign name,
// every IOC value). Two incidents end up in the same equivalence class iff they
// share at least one key. The pairwise match logic (with date-proximity and
// IOC threshold rules) then runs ONLY within each class. Practical complexity:
// ~O(n × avg_keys_per_incident); for the 490k bulk-load case this drops the
// previous O(n²) ~120B comparisons to ~5M.
//
// Transitivity is preserved by construction — if A shares a key with B and B
// shares a key (any key) with C, all three land in the same class and the
// existing groupIncidents inside the class handles the merge.
func MergeAll(incidents []*Incident) []*Incident {
	if len(incidents) == 0 {
		return nil
	}

	uf := newUnionFind(len(incidents))
	keyToFirstIdx := map[string]int{}
	addKey := func(idx int, key string) {
		if key == "" {
			return
		}
		if prev, ok := keyToFirstIdx[key]; ok {
			uf.Union(prev, idx)
		} else {
			keyToFirstIdx[key] = idx
		}
	}

	for i, inc := range incidents {
		for _, p := range inc.Packages {
			if p.Name != "" && p.Ecosystem != "" {
				addKey(i, "pkg:"+strings.ToLower(p.Ecosystem)+"/"+strings.ToLower(p.Name))
			}
		}
		if inc.Campaign.Name != "" {
			addKey(i, "campaign:"+strings.ToLower(inc.Campaign.Name))
		}
		// Cross-source CVE merging: CISA (KEV) and NVD (full CVE) produce
		// distinct incidents for the same CVE; merging by CVE_ID unifies them
		// so the merged record carries both exploited-in-wild flag (CISA) and
		// CVSS score (NVD).
		if inc.CVEExt != nil && inc.CVEExt.CVEID != "" {
			addKey(i, "cve:"+strings.ToLower(inc.CVEExt.CVEID))
		}
		for _, ioc := range collectIOCs(inc) {
			addKey(i, "ioc:"+strings.ToLower(ioc))
		}
	}

	// Materialise equivalence classes from the union-find.
	classes := map[int][]*Incident{}
	for i, inc := range incidents {
		root := uf.Find(i)
		classes[root] = append(classes[root], inc)
	}

	// Pairwise merge inside each class. The IOC-threshold + date-proximity
	// rule in shouldMerge still gates the final decision; bucketing only
	// narrows the candidate set.
	out := make([]*Incident, 0, len(incidents))
	for _, class := range classes {
		if len(class) == 1 {
			out = append(out, class[0])
			continue
		}
		for _, g := range groupIncidents(class) {
			out = append(out, mergeGroup(g))
		}
	}
	return out
}

// collectIOCs flattens every IOC value on an incident, used only as union-find
// keys. We deliberately don't include date proximity here — the date check is
// re-applied inside groupIncidents → shouldMerge.
func collectIOCs(inc *Incident) []string {
	var out []string
	for _, v := range inc.Indicators.Domains {
		out = append(out, v.Value)
	}
	for _, v := range inc.Indicators.IPs {
		out = append(out, v.Value)
	}
	for _, v := range inc.Indicators.URLs {
		out = append(out, v.Value)
	}
	for _, v := range inc.Indicators.FileHashes {
		out = append(out, v.Value)
	}
	return out
}

// unionFind is a textbook disjoint-set with path compression and union-by-rank.
type unionFind struct {
	parent []int
	rank   []int
}

func newUnionFind(n int) *unionFind {
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	return &unionFind{parent: parent, rank: make([]int, n)}
}

func (u *unionFind) Find(x int) int {
	for u.parent[x] != x {
		u.parent[x] = u.parent[u.parent[x]]
		x = u.parent[x]
	}
	return x
}

func (u *unionFind) Union(a, b int) {
	ra, rb := u.Find(a), u.Find(b)
	if ra == rb {
		return
	}
	if u.rank[ra] < u.rank[rb] {
		ra, rb = rb, ra
	}
	u.parent[rb] = ra
	if u.rank[ra] == u.rank[rb] {
		u.rank[ra]++
	}
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

func copyStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

func copyExposure(e Exposure) Exposure {
	return Exposure{
		LockfileSignatures: copyStrings(e.LockfileSignatures),
		FilePresence:       copyStrings(e.FilePresence),
		IDEArtifacts:       copyStrings(e.IDEArtifacts),
		Hooks:              copyStrings(e.Hooks),
		GitDependencies:    copyStrings(e.GitDependencies),
	}
}

// mergeIndicatorValues merges []IndicatorValue slices from all incidents in a
// group. Sources are unioned, Confidence recalculated, and any IP or Domain
// enrichment present on a secondary record is promoted to the merged entry if
// the primary lacks it.
func mergeIndicatorValues(group []*Incident, getSlice func(*Incident) []IndicatorValue, keyFn func(IndicatorValue) string) []IndicatorValue {
	m := map[string]*IndicatorValue{}
	for _, inc := range group {
		for i := range getSlice(inc) {
			v := getSlice(inc)[i]
			key := keyFn(v)
			if existing, ok := m[key]; ok {
				existing.Sources = unionStrings(append(existing.Sources, v.Sources...))
				existing.Confidence = confidence.Calculate(existing.Sources)
				if existing.IPEnrich == nil && v.IPEnrich != nil {
					existing.IPEnrich = v.IPEnrich
				}
				if existing.DomainEnrich == nil && v.DomainEnrich != nil {
					existing.DomainEnrich = v.DomainEnrich
				}
			} else {
				cp := v
				m[key] = &cp
			}
		}
	}
	out := make([]IndicatorValue, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	return out
}

// mergeGroup merges all incidents in a group into a single canonical incident.
func mergeGroup(group []*Incident) *Incident {
	if len(group) == 1 {
		return group[0]
	}

	base := *group[0]
	// Deep-copy slice-backed fields that mergeGroup doesn't fully rebuild,
	// preventing shared backing arrays with the original incident record.
	base.Exposure = copyExposure(group[0].Exposure)
	base.DetectionTargets = copyStrings(group[0].DetectionTargets)
	base.ActorIDs = copyStrings(group[0].ActorIDs)
	base.CrossDomainSources = copyStrings(group[0].CrossDomainSources)
	base.CrossDomainLinks = append([]CrossDomainLink(nil), group[0].CrossDomainLinks...)
	base.DetectionRules = append([]DetectionRule(nil), group[0].DetectionRules...)
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
	base.CVEExt = mergeCVEExt(group)

	return &base
}

// mergeCVEExt combines CVEExtension fields from all incidents in the group.
// Boolean flags are OR'd (any source saying true wins), CVSS keeps the highest
// score, and HTTPIndicators are union-merged by Value.
func mergeCVEExt(group []*Incident) *CVEExtension {
	var base *CVEExtension
	for _, inc := range group {
		if inc.CVEExt != nil {
			base = inc.CVEExt
			break
		}
	}
	if base == nil {
		return nil
	}
	// Make a shallow copy so we don't mutate the original.
	merged := *base
	for _, inc := range group {
		if inc.CVEExt == nil || inc.CVEExt == base {
			continue
		}
		ext := inc.CVEExt
		if ext.ExploitedInWild {
			merged.ExploitedInWild = true
		}
		if ext.ExploitPublic {
			merged.ExploitPublic = true
		}
		if ext.PatchAvailable {
			merged.PatchAvailable = true
		}
		if ext.CVSSScore > merged.CVSSScore {
			merged.CVSSScore = ext.CVSSScore
			merged.CVSSVector = ext.CVSSVector
		}
		if merged.ExploitType == "" && ext.ExploitType != "" {
			merged.ExploitType = ext.ExploitType
		}
		if merged.PatchURL == "" && ext.PatchURL != "" {
			merged.PatchURL = ext.PatchURL
		}
		merged.AffectedSoftware = unionAffectedSoftware(merged.AffectedSoftware, ext.AffectedSoftware)
		merged.HTTPIndicators = unionHTTPIndicators(merged.HTTPIndicators, ext.HTTPIndicators)
	}
	return &merged
}

func unionHTTPIndicators(a, b []HTTPIndicator) []HTTPIndicator {
	seen := map[string]bool{}
	out := make([]HTTPIndicator, 0, len(a)+len(b))
	for _, h := range append(a, b...) {
		key := h.Type + "|" + h.Value
		if !seen[key] {
			seen[key] = true
			out = append(out, h)
		}
	}
	return out
}

func unionAffectedSoftware(a, b []AffectedSoftware) []AffectedSoftware {
	seen := map[string]bool{}
	out := make([]AffectedSoftware, 0, len(a)+len(b))
	for _, s := range append(a, b...) {
		key := strings.ToLower(s.Vendor + "|" + s.Product)
		if !seen[key] {
			seen[key] = true
			out = append(out, s)
		}
	}
	return out
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

// maxReferencesPerIncident caps references on merged incidents. URLHaus and other
// bulk sources can accumulate hundreds of unique URLs for the same cluster.
const maxReferencesPerIncident = 20

func collectReferences(group []*Incident) []string {
	var all []string
	for _, inc := range group {
		all = append(all, inc.References...)
	}
	if len(all) > maxReferencesPerIncident {
		all = all[:maxReferencesPerIncident]
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

	out.Domains = mergeIndicatorValues(group, func(inc *Incident) []IndicatorValue { return inc.Indicators.Domains }, func(v IndicatorValue) string { return strings.ToLower(v.Value) })
	out.IPs = mergeIndicatorValues(group, func(inc *Incident) []IndicatorValue { return inc.Indicators.IPs }, func(v IndicatorValue) string { return v.Value })
	out.URLs = mergeIndicatorValues(group, func(inc *Incident) []IndicatorValue { return inc.Indicators.URLs }, func(v IndicatorValue) string { return strings.ToLower(v.Value) })

	// File hashes — different struct type; keyed by algorithm|value.
	hashMap := map[string]*FileHash{}
	for _, inc := range group {
		for _, h := range inc.Indicators.FileHashes {
			key := strings.ToLower(h.Algorithm + "|" + h.Value)
			if existing, ok := hashMap[key]; ok {
				existing.Sources = unionStrings(append(existing.Sources, h.Sources...))
				existing.Confidence = confidence.Calculate(existing.Sources)
			} else {
				cp := h
				hashMap[key] = &cp
			}
		}
	}
	for _, v := range hashMap {
		out.FileHashes = append(out.FileHashes, *v)
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

