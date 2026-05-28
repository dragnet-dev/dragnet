package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	urlpkg "net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const (
	baseURL    = "https://api.osv.dev/v1"
	bulkBase   = "https://storage.googleapis.com/osv-vulnerabilities"
	bulkCutoff = 7 * 24 * time.Hour // use bulk export when since > 7 days ago
	batchSize  = 100
)

// osvEcoName maps our internal ecosystem names to OSV ecosystem names.
var osvEcoName = map[string]string{
	"npm":            "npm",
	"pypi":           "PyPI",
	"cargo":          "crates.io",
	"maven":          "Maven",
	"nuget":          "NuGet",
	"rubygems":       "RubyGems",
	"go":             "Go",
	"hex":            "Hex",
	"packagist":      "Packagist",
	"pub":            "Pub",
	"github-actions": "GitHub Actions",
	// OS package ecosystems — used by os-packages module
	"debian": "Debian",
	"ubuntu": "Ubuntu",
	"alpine": "Alpine",
	"rhel":   "RHEL",
}

// localEcoName maps OSV ecosystem names back to our internal names.
var localEcoName = map[string]string{
	"npm":            "npm",
	"PyPI":           "pypi",
	"crates.io":      "cargo",
	"Maven":          "maven",
	"NuGet":          "nuget",
	"RubyGems":       "rubygems",
	"Go":             "go",
	"Hex":            "hex",
	"Packagist":      "packagist",
	"Pub":            "pub",
	"GitHub Actions": "github-actions",
	// OS package ecosystems
	"Debian": "debian",
	"Ubuntu": "ubuntu",
	"Alpine": "alpine",
	"RHEL":   "rhel",
}

// OSEcosystems is the set of OS package ecosystems used by the os-packages module.
var OSEcosystems = map[string]bool{
	"Debian": true,
	"Ubuntu": true,
	"Alpine": true,
	"RHEL":   true,
}

// bulkEcosystems are the ecosystems for which OSV publishes bulk exports.
//
// IMPORTANT: this is the canonical source of "package advisory" coverage for
// haul. Before adding another narrow advisory source (deps.dev, ecosystem-
// specific aggregators), check whether OSV already covers it here — most
// upstream advisory feeds end up in OSV within hours. Removed sources that
// duplicated this coverage: deps_dev (v3alpha retired), msrc (NVD covers).
var bulkEcosystems = []string{
	"npm", "PyPI", "crates.io",
	"Maven", "NuGet", "RubyGems", "Go", "Hex", "Packagist", "Pub",
	"GitHub Actions", // CI workflow action advisories
	// OS package ecosystems — fetched for the os-packages module
	"Debian", "Ubuntu", "Alpine", "RHEL",
}

// Client implements the Source interface for OSV.
type Client struct {
	http     *http.Client
	httpBulk *http.Client // separate client with longer timeout for bulk downloads
}

// New returns a new OSV client.
func New() *Client {
	return &Client{
		http:     &http.Client{Timeout: 30 * time.Second},
		httpBulk: &http.Client{Timeout: 5 * time.Minute},
	}
}

func (c *Client) Name() string { return "osv" }

// Fetch downloads OSV advisories modified since the given time.
// When since is more than 7 days ago it uses the bulk export; otherwise it
// returns nothing (enrichment via EnrichPackages covers routine syncs).
func (c *Client) Fetch(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	if time.Since(since) <= bulkCutoff {
		// Routine sync — bulk export is overkill; enrichment handles this path.
		return nil, nil
	}
	return c.fetchBulk(ctx, since)
}

// fetchBulk downloads each ecosystem's all.zip concurrently and returns
// advisories modified at or after since. Per-ecosystem errors are logged and
// skipped so a single unavailable ecosystem doesn't abort the full sync.
func (c *Client) fetchBulk(ctx context.Context, since time.Time) ([]*incident.Incident, error) {
	var mu sync.Mutex
	var all []*incident.Incident

	g, gctx := errgroup.WithContext(ctx)
	for _, eco := range bulkEcosystems {
		eco := eco
		g.Go(func() error {
			incs, err := c.fetchEcosystem(gctx, eco, since)
			if err != nil {
				log.Printf("[osv] bulk %s: %v (skipping)", eco, err)
				return nil // non-fatal: skip this ecosystem
			}
			log.Printf("[osv] bulk %s: %d advisories since %s", eco, len(incs), since.Format(time.RFC3339))
			mu.Lock()
			all = append(all, incs...)
			mu.Unlock()
			return nil
		})
	}
	return all, g.Wait()
}

// fetchEcosystem downloads and parses the all.zip for a single OSV ecosystem.
func (c *Client) fetchEcosystem(ctx context.Context, eco string, since time.Time) ([]*incident.Incident, error) {
	// Path-escape `eco` so ecosystems with spaces (e.g. "GitHub Actions") work.
	// Without this, the literal space in the URL would 000 the request.
	url := fmt.Sprintf("%s/%s/all.zip", bulkBase, urlpkg.PathEscape(eco))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpBulk.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, b)
	}

	// Write to a temp file — these zips can be 100-200 MB.
	tmp, err := os.CreateTemp("", "osv-bulk-*.zip")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return nil, err
	}

	info, err := tmp.Stat()
	if err != nil {
		return nil, err
	}

	zr, err := zip.NewReader(tmp, info.Size())
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	var incs []*incident.Incident
	// The npm/pypi all.zip files contain tens of thousands of JSON entries.
	// Check ctx every 256 files so a cancelled context exits the parse loop
	// promptly instead of churning for minutes after the parent ctx died.
	for i, f := range zr.File {
		if i&0xff == 0 {
			if err := ctx.Err(); err != nil {
				return incs, err
			}
		}
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}

		var adv osvAdvisory
		if err := json.Unmarshal(data, &adv); err != nil {
			continue
		}
		if adv.Modified.Before(since) {
			continue
		}
		inc := osvToIncident(&adv)
		if inc != nil {
			incs = append(incs, inc)
		}
	}
	return incs, nil
}

// EnrichPackages queries OSV's /v1/querybatch endpoint for a deduplicated list
// of packages and returns incidents for any advisories found.
func (c *Client) EnrichPackages(ctx context.Context, pkgs []incident.Package) ([]*incident.Incident, error) {
	// Build OSV queries only for ecosystems we have a mapping for.
	type osvQuery struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
	}

	var queries []osvQuery
	// Keep a mapping from query index → original package so we can map back.
	type pkgRef struct {
		name string
		eco  string // OSV ecosystem name
	}
	var refs []pkgRef

	for _, pkg := range pkgs {
		osvEco, ok := osvEcoName[strings.ToLower(pkg.Ecosystem)]
		if !ok {
			continue
		}
		var q osvQuery
		q.Package.Name = pkg.Name
		q.Package.Ecosystem = osvEco
		queries = append(queries, q)
		refs = append(refs, pkgRef{name: pkg.Name, eco: osvEco})
	}

	if len(queries) == 0 {
		return nil, nil
	}

	seen := map[string]bool{}
	var all []*incident.Incident

	for i := 0; i < len(queries); i += batchSize {
		if err := ctx.Err(); err != nil {
			return all, err
		}
		end := i + batchSize
		if end > len(queries) {
			end = len(queries)
		}
		batch := queries[i:end]

		body, err := json.Marshal(map[string]interface{}{"queries": batch})
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			baseURL+"/querybatch", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}

		var result struct {
			Results []struct {
				Vulns []osvAdvisory `json:"vulns"`
			} `json:"results"`
		}
		decErr := json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if decErr != nil {
			return nil, decErr
		}

		for _, r := range result.Results {
			for idx := range r.Vulns {
				adv := &r.Vulns[idx]
				if seen[adv.ID] {
					continue
				}
				seen[adv.ID] = true
				inc := osvToIncident(adv)
				if inc != nil {
					all = append(all, inc)
				}
			}
		}
	}

	return all, nil
}

// ── OSV schema types ───────────────────────────────────────────────────────

type osvAdvisory struct {
	ID        string    `json:"id"`
	Modified  time.Time `json:"modified"`
	Published time.Time `json:"published"`
	Aliases   []string  `json:"aliases"`
	Summary   string    `json:"summary"`
	Details   string    `json:"details"`
	Affected  []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

// osvToIncident converts an OSV advisory to an Incident.
func osvToIncident(adv *osvAdvisory) *incident.Incident {
	if adv.ID == "" || len(adv.Affected) == 0 {
		return nil
	}

	// Derive primary ecosystem from the first affected entry.
	primaryEco := localEcosystemName(adv.Affected[0].Package.Ecosystem)

	inc := &incident.Incident{
		ID:          primaryEco + "-osv-" + adv.ID,
		Source:      "osv",
		OSVID:       adv.ID,
		Description: osvDescription(adv),
		AttackType:  "malicious_publish",
		Severity:    osvSeverity(adv),
	}

	// Published timestamp — drives the 90-day curation window in index.json.
	if !adv.Published.IsZero() {
		inc.CompromiseWindow.Start = adv.Published.UTC().Format(time.RFC3339)
	} else if !adv.Modified.IsZero() {
		inc.CompromiseWindow.Start = adv.Modified.UTC().Format(time.RFC3339)
	}

	// GHSA alias
	for _, alias := range adv.Aliases {
		if strings.HasPrefix(alias, "GHSA-") {
			inc.GHSAID = alias
			break
		}
	}

	// Packages — skip entries with no name (e.g. GIT/GitHub ecosystem rows that
	// OSV includes alongside the real Hex/Go/etc. entry) or with an ecosystem we
	// can't map to a supported package manager.
	for _, a := range adv.Affected {
		if a.Package.Name == "" {
			continue
		}
		eco := localEcosystemName(a.Package.Ecosystem)
		if eco == "" {
			continue
		}
		inc.Packages = append(inc.Packages, incident.Package{
			Name:             a.Package.Name,
			Ecosystem:        eco,
			AffectedVersions: a.Versions,
		})
	}

	// References
	for _, ref := range adv.References {
		if ref.URL != "" {
			inc.References = append(inc.References, ref.URL)
		}
	}
	if len(inc.References) == 0 {
		inc.References = append(inc.References, "https://osv.dev/vulnerability/"+adv.ID)
	}

	return inc
}

func localEcosystemName(osvName string) string {
	if eco := localEcoName[osvName]; eco != "" {
		return eco
	}
	if base, _, ok := strings.Cut(osvName, ":"); ok {
		if eco := localEcoName[base]; eco != "" {
			return eco
		}
	}
	return strings.ToLower(osvName)
}

func osvDescription(adv *osvAdvisory) string {
	if summary := strings.TrimSpace(adv.Summary); summary != "" {
		return summary
	}
	if details := strings.TrimSpace(adv.Details); details != "" {
		return details
	}
	return "OSV advisory " + adv.ID
}

// osvSeverity derives a severity string from a CVSS score in an OSV advisory.
func osvSeverity(adv *osvAdvisory) string {
	for _, s := range adv.Severity {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			score := cvssBaseScore(s.Score)
			switch {
			case score >= 9.0:
				return "critical"
			case score >= 7.0:
				return "high"
			case score >= 4.0:
				return "medium"
			default:
				return "low"
			}
		}
	}
	switch strings.ToUpper(strings.TrimSpace(adv.DatabaseSpecific.Severity)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MODERATE", "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	}
	return "low"
}

// cvssBaseScore extracts the numeric CVSS base score from either a plain float
// string ("7.5") or a full CVSS v3.x vector string ("CVSS:3.1/AV:N/AC:L/...").
// OSV frequently returns vectors rather than pre-computed scores; computing the
// base score from the vector prevents critical advisories from being ranked as 0.
func cvssBaseScore(scoreOrVector string) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(scoreOrVector), 64)
	if err == nil {
		return f
	}
	if strings.HasPrefix(scoreOrVector, "CVSS:") {
		return parseCVSSv3BaseScore(scoreOrVector)
	}
	return 0
}

// parseCVSSv3BaseScore implements the CVSS v3.1 base score formula from a
// vector string. Returns 0 if the vector cannot be parsed.
// Spec: https://www.first.org/cvss/v3.1/specification-document §7.1-7.3
func parseCVSSv3BaseScore(vector string) float64 {
	// Strip version prefix ("CVSS:3.1/") and build a metric map.
	slash := strings.Index(vector, "/")
	if slash < 0 {
		return 0
	}
	metrics := map[string]string{}
	for _, part := range strings.Split(vector[slash+1:], "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	// Numeric lookup tables per CVSS v3.1 spec Table 14.
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	ac := map[string]float64{"L": 0.77, "H": 0.44}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	// PR values differ when Scope is Changed.
	prChanged := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	ui := map[string]float64{"N": 0.85, "R": 0.62}
	cia := map[string]float64{"N": 0.00, "L": 0.22, "H": 0.56}

	scope := metrics["S"]
	avVal, avOK := av[metrics["AV"]]
	acVal, acOK := ac[metrics["AC"]]
	uiVal, uiOK := ui[metrics["UI"]]
	cVal, cOK := cia[metrics["C"]]
	iVal, iOK := cia[metrics["I"]]
	aVal, aOK := cia[metrics["A"]]

	var prVal float64
	var prOK bool
	if scope == "C" {
		prVal, prOK = prChanged[metrics["PR"]]
	} else {
		prVal, prOK = pr[metrics["PR"]]
	}

	if !avOK || !acOK || !prOK || !uiOK || !cOK || !iOK || !aOK {
		return 0
	}

	iss := 1 - (1-cVal)*(1-iVal)*(1-aVal)
	var impact float64
	if scope == "C" {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}
	exploitability := 8.22 * avVal * acVal * prVal * uiVal
	base := impact + exploitability
	if base > 10 {
		base = 10
	}
	// CVSS roundup: ceiling to one decimal place.
	return math.Ceil(base*10) / 10
}
