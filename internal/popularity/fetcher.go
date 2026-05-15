package popularity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DownloadStats holds download metrics for a single package.
type DownloadStats struct {
	Weekly    int64
	Monthly   int64
	Total     int64
	FetchedAt time.Time
	Source    string
}

// httpGet is a thin wrapper for JSON GET requests.
func httpGet(ctx context.Context, url string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "dragnet/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// FetchDownloads retrieves weekly download counts for the given package.
// Returns nil stats (not an error) when the ecosystem lacks a download count API.
func FetchDownloads(ctx context.Context, ecosystem, packageName string) (*DownloadStats, error) {
	switch ecosystem {
	case "npm":
		return fetchNPM(ctx, packageName)
	case "pypi":
		return fetchPyPI(ctx, packageName)
	case "cargo":
		return fetchCargo(ctx, packageName)
	case "nuget":
		return fetchNuGet(ctx, packageName)
	case "rubygems":
		return fetchRubyGems(ctx, packageName)
	case "hex":
		return fetchHex(ctx, packageName)
	case "packagist":
		return fetchPackagist(ctx, packageName)
	case "pub":
		return fetchPub(ctx, packageName)
	case "go":
		// no public download count API for Go modules
		return nil, nil
	case "maven":
		// Maven Central does not expose download counts via its public API
		return nil, nil
	default:
		return nil, nil
	}
}

func fetchNPM(ctx context.Context, pkg string) (*DownloadStats, error) {
	var r struct {
		Downloads int64 `json:"downloads"`
	}
	url := "https://api.npmjs.org/downloads/point/last-week/" + pkg
	if err := httpGet(ctx, url, &r); err != nil {
		return nil, err
	}
	return &DownloadStats{Weekly: r.Downloads, FetchedAt: time.Now(), Source: "npmjs.org"}, nil
}

func fetchPyPI(ctx context.Context, pkg string) (*DownloadStats, error) {
	var r struct {
		Data struct {
			LastWeek int64 `json:"last_week"`
		} `json:"data"`
	}
	url := fmt.Sprintf("https://pypistats.org/api/packages/%s/recent?period=week", pkg)
	if err := httpGet(ctx, url, &r); err != nil {
		return nil, err
	}
	return &DownloadStats{Weekly: r.Data.LastWeek, FetchedAt: time.Now(), Source: "pypistats.org"}, nil
}

func fetchCargo(ctx context.Context, pkg string) (*DownloadStats, error) {
	var r struct {
		Crate struct {
			RecentDownloads int64 `json:"recent_downloads"`
			Downloads       int64 `json:"downloads"`
		} `json:"crate"`
	}
	url := "https://crates.io/api/v1/crates/" + pkg
	if err := httpGet(ctx, url, &r); err != nil {
		return nil, err
	}
	return &DownloadStats{
		Weekly:    r.Crate.RecentDownloads,
		Total:     r.Crate.Downloads,
		FetchedAt: time.Now(),
		Source:    "crates.io",
	}, nil
}

func fetchNuGet(ctx context.Context, pkg string) (*DownloadStats, error) {
	var r struct {
		TotalDownloads int64 `json:"totalDownloads"`
	}
	url := fmt.Sprintf("https://api.nuget.org/v3/registration5/%s/index.json", pkg)
	if err := httpGet(ctx, url, &r); err != nil {
		return nil, err
	}
	// NuGet only provides total; estimate weekly as total/52 for a rough proxy
	weekly := r.TotalDownloads / 52
	return &DownloadStats{Weekly: weekly, Total: r.TotalDownloads, FetchedAt: time.Now(), Source: "nuget.org"}, nil
}

func fetchRubyGems(ctx context.Context, pkg string) (*DownloadStats, error) {
	var r struct {
		Downloads        int64 `json:"downloads"`
		VersionDownloads int64 `json:"version_downloads"`
	}
	url := "https://rubygems.org/api/v1/gems/" + pkg + ".json"
	if err := httpGet(ctx, url, &r); err != nil {
		return nil, err
	}
	return &DownloadStats{
		Weekly:    r.VersionDownloads,
		Total:     r.Downloads,
		FetchedAt: time.Now(),
		Source:    "rubygems.org",
	}, nil
}

func fetchHex(ctx context.Context, pkg string) (*DownloadStats, error) {
	var r struct {
		Downloads struct {
			All    int64 `json:"all"`
			Recent int64 `json:"recent"`
		} `json:"downloads"`
	}
	url := "https://hex.pm/api/packages/" + pkg
	if err := httpGet(ctx, url, &r); err != nil {
		return nil, err
	}
	return &DownloadStats{Weekly: r.Downloads.Recent, Total: r.Downloads.All, FetchedAt: time.Now(), Source: "hex.pm"}, nil
}

func fetchPackagist(ctx context.Context, pkg string) (*DownloadStats, error) {
	var r struct {
		Package struct {
			Downloads struct {
				Total   int64 `json:"total"`
				Monthly int64 `json:"monthly"`
			} `json:"downloads"`
		} `json:"package"`
	}
	url := "https://packagist.org/packages/" + pkg + ".json"
	if err := httpGet(ctx, url, &r); err != nil {
		return nil, err
	}
	monthly := r.Package.Downloads.Monthly
	weekly := monthly / 4
	return &DownloadStats{
		Weekly:    weekly,
		Monthly:   monthly,
		Total:     r.Package.Downloads.Total,
		FetchedAt: time.Now(),
		Source:    "packagist.org",
	}, nil
}

func fetchPub(ctx context.Context, pkg string) (*DownloadStats, error) {
	var r struct {
		Metrics struct {
			Popularity float64 `json:"popularity"`
		} `json:"metrics"`
	}
	url := "https://pub.dev/api/packages/" + pkg
	if err := httpGet(ctx, url, &r); err != nil {
		return nil, err
	}
	// pub.dev reports a 0–1 popularity score; multiply by 10M for a rough weekly estimate
	weekly := int64(r.Metrics.Popularity * 10_000_000)
	return &DownloadStats{Weekly: weekly, FetchedAt: time.Now(), Source: "pub.dev"}, nil
}
