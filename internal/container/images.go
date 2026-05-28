package container

import (
	"encoding/json"
	"os"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

// PopularImage is a Docker Hub official image ranked by weekly pulls.
// Mirrors docker_hub.PopularImage to avoid a circular import.
type PopularImage struct {
	Repository  string `json:"repository"`
	WeeklyPulls int64  `json:"weekly_pulls"`
}

// LoadPopularImages reads popular image data from a JSON file.
func LoadPopularImages(path string) ([]PopularImage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var imgs []PopularImage
	if err := json.Unmarshal(data, &imgs); err != nil {
		return nil, err
	}
	return imgs, nil
}

// SavePopularImages writes popular image data to a JSON file.
func SavePopularImages(path string, imgs []PopularImage) error {
	data, err := json.MarshalIndent(imgs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// PopularIndex is a pre-built lookup table from repository name to weekly pull count.
// Build it once per sync cycle with BuildPopularIndex and reuse across calls.
type PopularIndex map[string]int64

// BuildPopularIndex constructs a PopularIndex from a slice of popular images.
func BuildPopularIndex(popular []PopularImage) PopularIndex {
	idx := make(PopularIndex, len(popular))
	for _, p := range popular {
		idx[p.Repository] = p.WeeklyPulls
	}
	return idx
}

// AffectsPopular returns true if any affected image's repository appears in
// idx with weekly pulls ≥ threshold. When no popular list has been configured
// (snapshot not yet generated), treat every image as in-scope rather than
// silently dropping all advisories — populating the snapshot via
// `dragnet update-popular --module container` is how users opt into strict
// filtering.
func AffectsPopular(affected []incident.AffectedImage, idx PopularIndex, threshold int64) bool {
	if len(idx) == 0 {
		return true
	}
	for _, img := range affected {
		if pulls, ok := idx[img.Repository]; ok && pulls >= threshold {
			return true
		}
	}
	return false
}
