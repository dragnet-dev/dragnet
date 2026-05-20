package osv

import "github.com/dragnet-dev/dragnet/internal/incident"

// OSFilter gates OS package advisories to high-signal records.
// Gate 1: severity must be "high" or "critical" (CVSS >= 7.0).
// Gate 2: at least one affected package must have a known fix version.
// Gate 3: if RequireFixOrKEV is set and no fix is present, the advisory must
//          be KEV-listed (ExploitedInWild on CVEExt).
//
// When ImagePackages is non-empty, an additional gate filters to packages that
// appear in at least one popular container image (populated by the container
// sync via state.WriteImagePackages). When empty, this gate is skipped so the
// module still works before the image package snapshot has been seeded.
type OSFilter struct {
	MinSeverity    string          // "high" or "critical"; default "high"
	ImagePackages  map[string]bool // package names present in popular images; nil = skip gate
	RequireFixOrKEV bool
}

// NewOSFilter returns an OSFilter with sensible defaults.
// imagePackages may be nil to disable the image-presence gate.
func NewOSFilter(imagePackages map[string]bool, requireFixOrKEV bool) *OSFilter {
	return &OSFilter{
		MinSeverity:     "high",
		ImagePackages:   imagePackages,
		RequireFixOrKEV: requireFixOrKEV,
	}
}

// Pass returns true if the advisory should be included in the os-packages module.
func (f *OSFilter) Pass(inc *incident.Incident) bool {
	// Gate 1: severity
	switch inc.Severity {
	case "high", "critical":
		// pass
	default:
		return false
	}

	// Gate 2: image packages presence (skipped when map is nil)
	if len(f.ImagePackages) > 0 {
		found := false
		for _, pkg := range inc.Packages {
			if f.ImagePackages[pkg.Name] {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Gate 3: require fix or KEV
	if f.RequireFixOrKEV {
		hasFix := false
		for _, pkg := range inc.Packages {
			if len(pkg.AffectedVersions) > 0 {
				hasFix = true
				break
			}
		}
		isKEV := inc.CVEExt != nil && inc.CVEExt.ExploitedInWild
		if !hasFix && !isKEV {
			return false
		}
	}

	return true
}

// FilterAll applies Pass to every incident and returns those that pass.
func (f *OSFilter) FilterAll(incidents []*incident.Incident) []*incident.Incident {
	out := make([]*incident.Incident, 0, len(incidents)/4)
	for _, inc := range incidents {
		if f.Pass(inc) {
			out = append(out, inc)
		}
	}
	return out
}
