package popularity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// PopularPackage is one entry in the top-N list for an ecosystem.
type PopularPackage struct {
	Name            string `json:"name"`
	WeeklyDownloads int64  `json:"weekly_downloads"`
	ImpactRating    string `json:"impact_rating"`
}

// PopularList is the on-disk format for state/popular_packages/{ecosystem}.json.
type PopularList struct {
	Generated time.Time        `json:"generated"`
	Ecosystem string           `json:"ecosystem"`
	Packages  []PopularPackage `json:"packages"`
}

// SavePopularList writes the list to dir/{ecosystem}.json.
func SavePopularList(dir, ecosystem string, packages []PopularPackage) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	list := PopularList{
		Generated: time.Now().UTC(),
		Ecosystem: ecosystem,
		Packages:  packages,
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ecosystem+".json"), data, 0o644)
}

// LoadPopularList reads state/popular_packages/{ecosystem}.json.
// Returns an empty slice (not an error) when the file does not exist.
func LoadPopularList(dir, ecosystem string) ([]PopularPackage, error) {
	path := filepath.Join(dir, ecosystem+".json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list PopularList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list.Packages, nil
}

// FetchPopularPackages retrieves the top-N packages by weekly downloads for an ecosystem.
// Not all ecosystems have a reliable top-N API; returns an empty slice for those.
func FetchPopularPackages(ctx context.Context, ecosystem string, n int) ([]PopularPackage, error) {
	switch ecosystem {
	case "npm":
		return fetchPopularNPM(ctx, n)
	case "pypi":
		return fetchPopularPyPI(ctx, n)
	case "cargo":
		return fetchPopularCargo(ctx, n)
	case "nuget":
		return fetchPopularNuGet(ctx, n)
	case "rubygems":
		return fetchPopularRubyGems(ctx, n)
	case "hex":
		return fetchPopularHex(ctx, n)
	case "packagist":
		return fetchPopularPackagist(ctx, n)
	case "pub":
		return fetchPopularPub(ctx, n)
	case "go", "maven":
		// no reliable top-N download API for these ecosystems
		return nil, nil
	case "github-actions":
		return fetchPopularActions(ctx, n)
	case "huggingface":
		return fetchPopularHF(ctx, n)
	default:
		return nil, nil
	}
}

func fetchPopularNPM(ctx context.Context, n int) ([]PopularPackage, error) {
	// npm provides download counts for specific packages, not ranked lists.
	// Use the npm registry search sorted by downloads as a proxy.
	var pkgs []PopularPackage
	pageSize := 250
	for offset := 0; len(pkgs) < n; offset += pageSize {
		var r struct {
			Objects []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
				Downloads struct {
					Weekly int64 `json:"weekly"`
				} `json:"downloads"`
			} `json:"objects"`
		}
		url := fmt.Sprintf("https://registry.npmjs.org/-/v1/search?text=boost:popularity&size=%d&from=%d", pageSize, offset)
		if err := httpGet(ctx, url, &r); err != nil {
			return pkgs, err
		}
		if len(r.Objects) == 0 {
			break
		}
		for _, obj := range r.Objects {
			rating := string(ComputeImpactRating(obj.Downloads.Weekly))
			pkgs = append(pkgs, PopularPackage{
				Name:            obj.Package.Name,
				WeeklyDownloads: obj.Downloads.Weekly,
				ImpactRating:    rating,
			})
		}
	}
	if len(pkgs) > n {
		pkgs = pkgs[:n]
	}
	return pkgs, nil
}

func fetchPopularPyPI(ctx context.Context, n int) ([]PopularPackage, error) {
	var r []struct {
		Package   string `json:"package"`
		Downloads int64  `json:"downloads"`
	}
	url := "https://pypistats.org/api/packages/top?limit=5000"
	if err := httpGet(ctx, url, &r); err != nil {
		return nil, err
	}
	var pkgs []PopularPackage
	for i, item := range r {
		if i >= n {
			break
		}
		pkgs = append(pkgs, PopularPackage{
			Name:            item.Package,
			WeeklyDownloads: item.Downloads,
			ImpactRating:    string(ComputeImpactRating(item.Downloads)),
		})
	}
	return pkgs, nil
}

func fetchPopularCargo(ctx context.Context, n int) ([]PopularPackage, error) {
	var pkgs []PopularPackage
	perPage := 100
	for page := 1; len(pkgs) < n; page++ {
		var r struct {
			Crates []struct {
				Name            string `json:"name"`
				RecentDownloads int64  `json:"recent_downloads"`
			} `json:"crates"`
		}
		url := fmt.Sprintf("https://crates.io/api/v1/crates?sort=downloads&per_page=%d&page=%d", perPage, page)
		if err := httpGet(ctx, url, &r); err != nil {
			return pkgs, err
		}
		if len(r.Crates) == 0 {
			break
		}
		for _, c := range r.Crates {
			pkgs = append(pkgs, PopularPackage{
				Name:            c.Name,
				WeeklyDownloads: c.RecentDownloads,
				ImpactRating:    string(ComputeImpactRating(c.RecentDownloads)),
			})
		}
	}
	if len(pkgs) > n {
		pkgs = pkgs[:n]
	}
	return pkgs, nil
}

func fetchPopularNuGet(ctx context.Context, n int) ([]PopularPackage, error) {
	var pkgs []PopularPackage
	skip := 0
	take := 100
	for len(pkgs) < n {
		var r struct {
			Data []struct {
				ID             string `json:"id"`
				TotalDownloads int64  `json:"totalDownloads"`
			} `json:"data"`
		}
		url := fmt.Sprintf("https://api.nuget.org/v3/query?q=*&sortBy=totalDownloads&take=%d&skip=%d", take, skip)
		if err := httpGet(ctx, url, &r); err != nil {
			return pkgs, err
		}
		if len(r.Data) == 0 {
			break
		}
		for _, item := range r.Data {
			weekly := item.TotalDownloads / 52
			pkgs = append(pkgs, PopularPackage{
				Name:            item.ID,
				WeeklyDownloads: weekly,
				ImpactRating:    string(ComputeImpactRating(weekly)),
			})
		}
		skip += take
	}
	if len(pkgs) > n {
		pkgs = pkgs[:n]
	}
	return pkgs, nil
}

func fetchPopularRubyGems(ctx context.Context, n int) ([]PopularPackage, error) {
	var pkgs []PopularPackage
	for page := 1; len(pkgs) < n; page++ {
		var r []struct {
			Name             string `json:"name"`
			VersionDownloads int64  `json:"version_downloads"`
		}
		url := fmt.Sprintf("https://rubygems.org/api/v1/gems.json?sort=downloads&page=%d", page)
		if err := httpGet(ctx, url, &r); err != nil {
			return pkgs, err
		}
		if len(r) == 0 {
			break
		}
		for _, g := range r {
			pkgs = append(pkgs, PopularPackage{
				Name:            g.Name,
				WeeklyDownloads: g.VersionDownloads,
				ImpactRating:    string(ComputeImpactRating(g.VersionDownloads)),
			})
		}
	}
	if len(pkgs) > n {
		pkgs = pkgs[:n]
	}
	return pkgs, nil
}

func fetchPopularHex(ctx context.Context, n int) ([]PopularPackage, error) {
	var pkgs []PopularPackage
	for page := 1; len(pkgs) < n; page++ {
		var r []struct {
			Name      string `json:"name"`
			Downloads struct {
				All    int64 `json:"all"`
				Recent int64 `json:"recent"`
			} `json:"downloads"`
		}
		url := fmt.Sprintf("https://hex.pm/api/packages?sort=downloads&page=%d", page)
		if err := httpGet(ctx, url, &r); err != nil {
			return pkgs, err
		}
		if len(r) == 0 {
			break
		}
		for _, p := range r {
			pkgs = append(pkgs, PopularPackage{
				Name:            p.Name,
				WeeklyDownloads: p.Downloads.Recent,
				ImpactRating:    string(ComputeImpactRating(p.Downloads.Recent)),
			})
		}
	}
	if len(pkgs) > n {
		pkgs = pkgs[:n]
	}
	return pkgs, nil
}

func fetchPopularPackagist(ctx context.Context, n int) ([]PopularPackage, error) {
	var pkgs []PopularPackage
	for page := 1; len(pkgs) < n; page++ {
		var r struct {
			Results []struct {
				Name      string `json:"name"`
				Downloads int64  `json:"downloads"`
			} `json:"results"`
			Next string `json:"next"`
		}
		url := fmt.Sprintf("https://packagist.org/search.json?q=*&numperpage=100&page=%d", page)
		if err := httpGet(ctx, url, &r); err != nil {
			return pkgs, err
		}
		if len(r.Results) == 0 {
			break
		}
		for _, item := range r.Results {
			// Packagist search returns total downloads; estimate weekly as monthly/4
			weekly := item.Downloads / 48
			pkgs = append(pkgs, PopularPackage{
				Name:            item.Name,
				WeeklyDownloads: weekly,
				ImpactRating:    string(ComputeImpactRating(weekly)),
			})
		}
		if r.Next == "" {
			break
		}
	}
	if len(pkgs) > n {
		pkgs = pkgs[:n]
	}
	return pkgs, nil
}

func fetchPopularPub(ctx context.Context, n int) ([]PopularPackage, error) {
	var pkgs []PopularPackage
	nextURL := "https://pub.dev/api/packages?ordering=popularity"
	for len(pkgs) < n && nextURL != "" {
		var r struct {
			Packages []struct {
				Name string `json:"name"`
			} `json:"packages"`
			NextURL string `json:"nextUrl"`
		}
		if err := httpGet(ctx, nextURL, &r); err != nil {
			return pkgs, err
		}
		if len(r.Packages) == 0 {
			break
		}
		// pub.dev orders by popularity score (0–1) but doesn't expose raw counts.
		// Use rank position as a proxy: rank 1 ≈ 10M/week, decaying by rank.
		for _, p := range r.Packages {
			rank := int64(len(pkgs) + 1)
			weekly := int64(10_000_000) / rank
			pkgs = append(pkgs, PopularPackage{
				Name:            p.Name,
				WeeklyDownloads: weekly,
				ImpactRating:    string(ComputeImpactRating(weekly)),
			})
		}
		nextURL = r.NextURL
	}
	if len(pkgs) > n {
		pkgs = pkgs[:n]
	}
	return pkgs, nil
}

// popularActionsPath is the default path for the GitHub Actions popular list.
// Callers may override this by setting the DRAGNET_POPULAR_ACTIONS_PATH env var.
const defaultPopularActionsPath = "state/popular_actions.json"

type popularActionEntry struct {
	Name     string `json:"name"`
	Official bool   `json:"official"`
}

type popularActionList struct {
	Generated time.Time            `json:"generated"`
	Actions   []popularActionEntry `json:"actions"`
}

// fetchPopularActions reads the seeded popular_actions.json and returns it as
// []PopularPackage. There is no live ranking API for GitHub Actions.
func fetchPopularActions(_ context.Context, n int) ([]PopularPackage, error) {
	path := os.Getenv("DRAGNET_POPULAR_ACTIONS_PATH")
	if path == "" {
		path = defaultPopularActionsPath
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list popularActionList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	var pkgs []PopularPackage
	for _, a := range list.Actions {
		if len(pkgs) >= n {
			break
		}
		pkgs = append(pkgs, PopularPackage{
			Name:            a.Name,
			WeeklyDownloads: 0,
			ImpactRating:    "high",
		})
	}
	return pkgs, nil
}

// fetchPopularHF fetches the top-n models by downloads from the Hugging Face Hub API.
func fetchPopularHF(ctx context.Context, n int) ([]PopularPackage, error) {
	url := fmt.Sprintf("https://huggingface.co/api/models?sort=downloads&direction=-1&limit=%d", n)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HF API returned %d", resp.StatusCode)
	}

	var models []struct {
		ID        string `json:"id"`
		Downloads int64  `json:"downloads"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&models); err != nil {
		return nil, err
	}

	pkgs := make([]PopularPackage, 0, len(models))
	for _, m := range models {
		pkgs = append(pkgs, PopularPackage{
			Name:            m.ID,
			WeeklyDownloads: m.Downloads,
			ImpactRating:    string(ComputeImpactRating(m.Downloads)),
		})
	}
	return pkgs, nil
}
