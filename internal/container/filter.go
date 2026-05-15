package container

import "github.com/dragnet-dev/dragnet/internal/incident"

// Config holds tunable parameters for the three-tier CVE filter.
type Config struct {
	Tier2CVSS             float64 // minimum CVSS for Tier 2 (default 9.0)
	Tier3CVSS             float64 // minimum CVSS for Tier 3 (default 7.0)
	PopularImageThreshold int64   // minimum weekly pulls to be in scope
}

// DefaultConfig returns production-safe defaults.
func DefaultConfig() Config {
	return Config{
		Tier2CVSS:             9.0,
		Tier3CVSS:             7.0,
		PopularImageThreshold: 1_000_000,
	}
}

// Tier classifies a CVE into a tier (1–3) or returns 0 if it should not be indexed.
//
//	Tier 1: CISA KEV (exploited in the wild)
//	Tier 2: CVSS ≥ cfg.Tier2CVSS
//	Tier 3: CVSS ≥ cfg.Tier3CVSS AND public PoC available
//
// Returns 0 if no tier matches or if the CVE doesn't affect any popular image.
func Tier(
	cvss float64,
	exploitedInWild, hasPublicPoC bool,
	affected []incident.AffectedImage,
	popular []PopularImage,
	cfg Config,
) int {
	if !AffectsPopular(affected, popular, cfg.PopularImageThreshold) {
		return 0
	}
	if exploitedInWild {
		return 1
	}
	if cvss >= cfg.Tier2CVSS {
		return 2
	}
	if cvss >= cfg.Tier3CVSS && hasPublicPoC {
		return 3
	}
	return 0
}
