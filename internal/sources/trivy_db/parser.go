package trivy_db

import (
	"fmt"
	"strings"
	"time"

	trivytypes "github.com/aquasecurity/trivy-db/pkg/types"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

// advisoriesToImages converts OS advisory entries for a given family + CVE into
// AffectedImage records. Each unique (repository, os_family) tuple is one record.
func advisoriesToImages(cveID, osFamily string, advisories []trivytypes.Advisory) []incident.AffectedImage {
	type key struct{ repo, family string }
	byRepo := map[key]*incident.AffectedImage{}

	for _, adv := range advisories {
		// Map OS package names to official Docker Hub image repositories.
		repos := pkgToRepos(adv.VulnerabilityID, osFamily)
		if len(repos) == 0 {
			// Fall back to generic: use the package name as the image hint.
			repos = []string{strings.ToLower(cveID)}
		}

		for _, repo := range repos {
			k := key{repo, osFamily}
			if _, ok := byRepo[k]; !ok {
				byRepo[k] = &incident.AffectedImage{
					Repository: repo,
					OSFamily:   osFamily,
					CVEIDs:     []string{cveID},
					Confidence: 0.85,
					Sources:    []string{"trivy_db"},
				}
			}
			if adv.FixedVersion != "" {
				byRepo[k].FixedTag = adv.FixedVersion
			}
			// Vulnerable versions come from AffectedVersion or VulnerableVersions
			if adv.AffectedVersion != "" {
				byRepo[k].VulnerableTags = appendUniq(byRepo[k].VulnerableTags, adv.AffectedVersion)
			}
			for _, v := range adv.VulnerableVersions {
				byRepo[k].VulnerableTags = appendUniq(byRepo[k].VulnerableTags, v)
			}
		}
	}

	out := make([]incident.AffectedImage, 0, len(byRepo))
	for _, img := range byRepo {
		out = append(out, *img)
	}
	return out
}

// mapToIncident constructs a container_vulnerability Incident from Trivy data.
func mapToIncident(
	cveID string,
	cvss float64,
	vuln trivytypes.Vulnerability,
	affected []incident.AffectedImage,
) *incident.Incident {
	year := time.Now().UTC().Format("2006")
	if vuln.PublishedDate != nil {
		year = vuln.PublishedDate.Format("2006")
	}

	severity := cvssToSeverity(cvss)

	refs := make([]string, 0, len(vuln.References)+1)
	refs = append(refs, fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID))
	for _, r := range vuln.References {
		if r != "" {
			refs = append(refs, r)
		}
	}

	desc := vuln.Description
	if desc == "" {
		desc = fmt.Sprintf("CVE %s affects container base images (CVSS %.1f).", cveID, cvss)
	}

	// ID will be overwritten by the Dragnet ID registry during merge.
	// We use a provisional ID derived from the CVE to allow dedup before assignment.
	provisionalID := fmt.Sprintf("container-%s-%s-0000", strings.ToLower(strings.ReplaceAll(cveID, "-", "")), year)

	var compStart string
	if vuln.PublishedDate != nil {
		compStart = vuln.PublishedDate.UTC().Format(time.RFC3339)
	}

	return &incident.Incident{
		ID:          provisionalID,
		Source:      "trivy_db",
		AttackType:  "container_vulnerability",
		Severity:    severity,
		Description: desc,
		References:  refs,
		CompromiseWindow: incident.CompromiseWindow{
			Start: compStart,
		},
		ContainerExt: &incident.ContainerExtension{
			AffectedImages: affected,
			CVSS:           cvss,
		},
	}
}

// bestCVSS extracts the highest available CVSS score from a VendorCVSS map,
// preferring v3 over v2.
func bestCVSS(vendorCVSS trivytypes.VendorCVSS) float64 {
	var best float64
	for _, c := range vendorCVSS {
		if c.V3Score > best {
			best = c.V3Score
		}
	}
	if best == 0 {
		for _, c := range vendorCVSS {
			if c.V2Score > best {
				best = c.V2Score
			}
		}
	}
	return best
}

// cvssToSeverity maps a CVSS v3 base score to a Dragnet severity string.
func cvssToSeverity(score float64) string {
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

// pkgToRepos maps an OS package name to Docker Hub repository names that
// typically include that package as part of their base layer.
// This is a best-effort heuristic — the three-tier filter further narrows scope.
var pkgToImageMap = map[string][]string{
	"openssl":      {"node", "python", "ruby", "nginx", "redis", "postgres", "mysql"},
	"libssl3":      {"node", "python", "nginx", "redis"},
	"libssl1.1":    {"node", "python", "nginx"},
	"libcurl":      {"node", "python", "ruby", "nginx"},
	"libcurl4":     {"node", "python", "nginx"},
	"zlib1g":       {"node", "python", "ruby", "nginx", "redis"},
	"glibc":        {"node", "python", "ruby", "go", "java"},
	"busybox":      {"node", "python", "ruby", "nginx", "redis", "postgres", "alpine"},
	"musl":         {"node", "python", "alpine", "nginx"},
	"expat":        {"python", "node"},
	"libexpat1":    {"python", "node"},
	"libxml2":      {"python", "node", "ruby", "php"},
	"sqlite3":      {"python", "ruby", "php"},
	"libsqlite3-0": {"python", "ruby"},
}

func pkgToRepos(pkgName, _ string) []string {
	return pkgToImageMap[strings.ToLower(pkgName)]
}

func appendUniq(s []string, v string) []string {
	for _, existing := range s {
		if existing == v {
			return s
		}
	}
	return append(s, v)
}
