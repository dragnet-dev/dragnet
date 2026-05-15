package popularity

// ImpactRating classifies a package by its weekly download volume.
type ImpactRating string

const (
	ImpactCritical   ImpactRating = "critical"   // >= 1M/week
	ImpactHigh       ImpactRating = "high"       // >= 100k/week
	ImpactMedium     ImpactRating = "medium"     // >= 10k/week
	ImpactLow        ImpactRating = "low"        // >= 1k/week
	ImpactNegligible ImpactRating = "negligible" // < 1k/week
)

// ComputeImpactRating returns the rating for a given weekly download count.
func ComputeImpactRating(weeklyDownloads int64) ImpactRating {
	switch {
	case weeklyDownloads >= 1_000_000:
		return ImpactCritical
	case weeklyDownloads >= 100_000:
		return ImpactHigh
	case weeklyDownloads >= 10_000:
		return ImpactMedium
	case weeklyDownloads >= 1_000:
		return ImpactLow
	default:
		return ImpactNegligible
	}
}
