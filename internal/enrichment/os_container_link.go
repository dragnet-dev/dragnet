package enrichment

import (
	"strings"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

// LinkOSToContainer creates cross-domain links between os-packages incidents
// and container incidents that share a CVE ID. It also adds a package-version
// IOC to any container incident where the vulnerable OS package is referenced.
//
// Links are written in both directions: the os-packages incident gets a
// "shared_cve" link pointing at the container incident, and vice versa.
func LinkOSToContainer(
	osIncidents []*incident.Incident,
	containerIncidents []*incident.Incident,
) {
	if len(osIncidents) == 0 || len(containerIncidents) == 0 {
		return
	}

	// Build CVE ID → container incident reverse index.
	// Container incidents store CVE IDs in CVEExt.CVEID and in
	// ContainerExt.AffectedImages[*].CVEIDs.
	cveToContainer := map[string][]*incident.Incident{}
	for _, inc := range containerIncidents {
		var cveIDs []string
		if inc.CVEExt != nil && inc.CVEExt.CVEID != "" {
			cveIDs = append(cveIDs, inc.CVEExt.CVEID)
		}
		if inc.ContainerExt != nil {
			for _, img := range inc.ContainerExt.AffectedImages {
				for _, id := range img.CVEIDs {
					cveIDs = append(cveIDs, id)
				}
			}
		}
		for _, id := range cveIDs {
			cveToContainer[id] = appendIncOnce(cveToContainer[id], inc)
		}
	}

	if len(cveToContainer) == 0 {
		return
	}

	// For each os-packages incident, collect its CVE IDs and link to matching
	// container incidents.
	for _, osInc := range osIncidents {
		var cveIDs []string
		// OSV advisories use OSVID which may be a CVE-YYYY-NNNNN string or a
		// GHSA- string. Pull the CVE ID from CVEExt when set (NVD enrichment).
		if osInc.CVEExt != nil && osInc.CVEExt.CVEID != "" {
			cveIDs = append(cveIDs, osInc.CVEExt.CVEID)
		}
		// Also check OSVID — OSV sometimes uses CVE IDs directly as the advisory ID.
		if strings.HasPrefix(osInc.OSVID, "CVE-") {
			cveIDs = appendStrOnce(cveIDs, osInc.OSVID)
		}

		if len(cveIDs) == 0 {
			continue
		}

		linkedContainers := map[*incident.Incident]string{} // inc → first CVE ID matched
		for _, cveID := range cveIDs {
			for _, containerInc := range cveToContainer[cveID] {
				if _, already := linkedContainers[containerInc]; !already {
					linkedContainers[containerInc] = cveID
				}
			}
		}

		for containerInc, cveID := range linkedContainers {
			// os-packages → container link
			osInc.CrossDomainLinks = appendLinkOnce(
				osInc.CrossDomainLinks,
				incident.CrossDomainLink{
					Module:       "container",
					IncidentID:   containerInc.ID,
					Relationship: "shared_cve",
					SharedIOC: &incident.SharedIOC{
						Type:  "cve",
						Value: cveID,
					},
					Confidence: 0.9,
				},
			)

			// container → os-packages link
			containerInc.CrossDomainLinks = appendLinkOnce(
				containerInc.CrossDomainLinks,
				incident.CrossDomainLink{
					Module:       "os-packages",
					IncidentID:   osInc.ID,
					Relationship: "shared_cve",
					SharedIOC: &incident.SharedIOC{
						Type:  "cve",
						Value: cveID,
					},
					Confidence: 0.9,
				},
			)

			// Add package-version IOC to the container incident for each OS package
			// version affected, so tools can match against installed package DBs.
			for _, pkg := range osInc.Packages {
				for _, ver := range pkg.AffectedVersions {
					iocVal := pkg.Name + "/" + ver
					containerInc.Indicators.URLs = appendURLOnce(containerInc.Indicators.URLs,
						incident.IndicatorValue{
							Value:      iocVal,
							Sources:    []string{"os-packages"},
							Confidence: 0.85,
						})
				}
			}
		}
	}
}

func appendIncOnce(incs []*incident.Incident, inc *incident.Incident) []*incident.Incident {
	for _, existing := range incs {
		if existing == inc {
			return incs
		}
	}
	return append(incs, inc)
}

func appendStrOnce(ss []string, s string) []string {
	for _, v := range ss {
		if v == s {
			return ss
		}
	}
	return append(ss, s)
}

func appendURLOnce(urls []incident.IndicatorValue, v incident.IndicatorValue) []incident.IndicatorValue {
	for _, u := range urls {
		if u.Value == v.Value {
			return urls
		}
	}
	return append(urls, v)
}
