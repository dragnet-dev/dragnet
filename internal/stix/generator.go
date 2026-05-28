package stix

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/dragnet-dev/dragnet/internal/actor"
	"github.com/dragnet-dev/dragnet/internal/incident"
)

// actorStore is set at startup by SetActorStore so GenerateBundle can enrich
// bundles with full intrusion-set objects and TTP relationships.
var actorStore *actor.Store

// SetActorStore wires the global actor store used during bundle generation.
func SetActorStore(s *actor.Store) { actorStore = s }

var attackTypeToIndicatorTypes = map[string][]string{
	"account_takeover":    {"malicious-activity", "compromised"},
	"typosquat":           {"malicious-activity", "attribution"},
	"dep_confusion":       {"malicious-activity"},
	"poisoned_maintainer": {"malicious-activity", "compromised"},
	"malicious_publish":   {"malicious-activity"},
	"ci_poisoning":        {"malicious-activity", "compromised"},
	"namespace_squatting": {"malicious-activity", "attribution"},
	"vulnerability":       {"malicious-activity"},
	"exploit":             {"malicious-activity"},
	"ransomware":          {"malicious-activity"},
}

var attackTypeToMalwareTypes = map[string][]string{
	"account_takeover":    {"credential-stealer"},
	"malicious_publish":   {"trojan"},
	"poisoned_maintainer": {"trojan"},
	"dep_confusion":       {"trojan"},
	"ci_poisoning":        {"backdoor"},
	"typosquat":           {"trojan"},
	"namespace_squatting": {"trojan"},
	"ransomware":          {"ransomware"},
}

var supplyChainAttackTypes = map[string]bool{
	"account_takeover":    true,
	"typosquat":           true,
	"dep_confusion":       true,
	"poisoned_maintainer": true,
	"malicious_publish":   true,
	"ci_poisoning":        true,
	"namespace_squatting": true,
}

func labelsForAttackType(attackType string) []string {
	if supplyChainAttackTypes[attackType] {
		return []string{"supply-chain"}
	}
	switch attackType {
	case "vulnerability", "exploit":
		return []string{"vulnerability"}
	case "ransomware":
		return []string{"ransomware"}
	default:
		return []string{"threat"}
	}
}

var campaignConfidenceMap = map[string]float64{
	"low":    0.40,
	"medium": 0.65,
	"high":   0.85,
}

func toSTIXConfidence(c float64) int {
	v := int(c * 100)
	if v > 100 {
		return 100
	}
	return v
}

func refsFromReferences(references []string) []ExternalRef {
	refs := make([]ExternalRef, 0, len(references))
	for _, r := range references {
		refs = append(refs, ExternalRef{SourceName: "dragnet", URL: r})
	}
	return refs
}

func mitreURL(id string) string {
	// T1195.002 → https://attack.mitre.org/techniques/T1195/002
	return "https://attack.mitre.org/techniques/" + strings.ReplaceAll(id, ".", "/")
}

func rel(now time.Time, relType, srcID, tgtID string, labels []string) Relationship {
	return Relationship{
		Common: Common{
			Type:        "relationship",
			ID:          StixID("relationship", srcID+":"+relType+":"+tgtID),
			SpecVersion: "2.1",
			Created:     now,
			Modified:    now,
			Labels:      labels,
		},
		RelationshipType: relType,
		SourceRef:        srcID,
		TargetRef:        tgtID,
	}
}

// GenerateBundle converts a Dragnet incident into a STIX 2.1 bundle.
func GenerateBundle(inc *incident.Incident) Bundle {
	now := time.Now().UTC()
	objects := []any{}

	// Identity — Dragnet as the intelligence source (constant across all bundles)
	dragnetID := StixID("identity", "dragnet")
	objects = append(objects, Identity{
		Common: Common{
			Type:        "identity",
			ID:          dragnetID,
			SpecVersion: "2.1",
			Created:     now,
			Modified:    now,
		},
		Name:          "Dragnet",
		IdentityClass: "system",
		Description:   "Open source supply chain threat intelligence. https://dragnet.dev",
	})

	// Vulnerability — only when OSV or GHSA ID is present
	var vulnID string
	if inc.OSVID != "" || inc.GHSAID != "" {
		name := inc.OSVID
		if name == "" {
			name = inc.GHSAID
		}
		vulnID = StixID("vulnerability", name)
		refs := []ExternalRef{}
		if inc.OSVID != "" {
			refs = append(refs, ExternalRef{
				SourceName: "osv",
				ExternalID: inc.OSVID,
				URL:        "https://osv.dev/vulnerability/" + inc.OSVID,
			})
		}
		if inc.GHSAID != "" {
			refs = append(refs, ExternalRef{
				SourceName: "github",
				ExternalID: inc.GHSAID,
				URL:        "https://github.com/advisories/" + inc.GHSAID,
			})
		}
		objects = append(objects, Vulnerability{
			Common: Common{
				Type:         "vulnerability",
				ID:           vulnID,
				SpecVersion:  "2.1",
				Created:      now,
				Modified:     now,
				Labels:       labelsForAttackType(inc.AttackType),
				ExternalRefs: refs,
			},
			Name:        name,
			Description: inc.Description,
		})
	}

	// Campaign
	var campaignID string
	if inc.Campaign.Name != "" {
		campaignID = StixID("campaign", inc.Campaign.Name)
		conf := campaignConfidenceMap[inc.Campaign.Confidence]
		objects = append(objects, Campaign{
			Common: Common{
				Type:         "campaign",
				ID:           campaignID,
				SpecVersion:  "2.1",
				Created:      now,
				Modified:     now,
				Confidence:   toSTIXConfidence(conf),
				Labels:       labelsForAttackType(inc.AttackType),
				ExternalRefs: refsFromReferences(inc.References),
			},
			Name:        inc.Campaign.Name,
			Description: inc.Description,
		})
	}

	// ThreatActor
	var actorID string
	if inc.Campaign.Actor != "" {
		actorID = StixID("threat-actor", inc.Campaign.Actor)
		objects = append(objects, ThreatActor{
			Common: Common{
				Type:        "threat-actor",
				ID:          actorID,
				SpecVersion: "2.1",
				Created:     now,
				Modified:    now,
				Labels:      labelsForAttackType(inc.AttackType),
			},
			Name:             inc.Campaign.Actor,
			ThreatActorTypes: []string{"criminal"},
		})
		if campaignID != "" {
			objects = append(objects, rel(now, "attributed-to", campaignID, actorID, labelsForAttackType(inc.AttackType)))
		}

		// IntrusionSet — emitted when an actor profile exists in the store.
		if actorStore != nil {
			if profile, ok := actorStore.Lookup(inc.Campaign.Actor); ok {
				isID := StixID("intrusion-set", profile.ID)
				objects = append(objects, IntrusionSet{
					Common: Common{
						Type:        "intrusion-set",
						ID:          isID,
						SpecVersion: "2.1",
						Created:     now,
						Modified:    now,
						Labels:      labelsForAttackType(inc.AttackType),
					},
					Name:        profile.Name,
					Description: profile.Description,
					Aliases:     profile.Aliases,
					FirstSeen:   profile.FirstSeen,
					LastSeen:    profile.LastSeen,
				})
				// threat-actor part-of intrusion-set
				objects = append(objects, rel(now, "part-of", actorID, isID, labelsForAttackType(inc.AttackType)))
				// intrusion-set uses each known TTP
				for _, ttp := range profile.TTPs {
					apID := StixID("attack-pattern", ttp.ID)
					objects = append(objects, AttackPattern{
						Common: Common{
							Type:        "attack-pattern",
							ID:          apID,
							SpecVersion: "2.1",
							Created:     now,
							Modified:    now,
							ExternalRefs: []ExternalRef{{
								SourceName: "mitre-attack",
								ExternalID: ttp.ID,
								URL:        mitreURL(ttp.ID),
							}},
						},
						Name: ttp.Name,
					})
					objects = append(objects, rel(now, "uses", isID, apID, labelsForAttackType(inc.AttackType)))
				}
			}
		}
	}

	// Secondary actors — emit intrusion-set objects for all attributed actor IDs
	// beyond the one already covered by Campaign.Actor above.
	if actorStore != nil {
		primaryProfileID := ""
		if inc.Campaign.Actor != "" {
			if p, ok := actorStore.Lookup(inc.Campaign.Actor); ok {
				primaryProfileID = p.ID
			}
		}
		for _, slug := range inc.ActorIDs {
			if slug == primaryProfileID {
				continue // already emitted above
			}
			profile, ok := actorStore.LookupByID(slug)
			if !ok {
				continue
			}
			isID := StixID("intrusion-set", profile.ID)
			objects = append(objects, IntrusionSet{
				Common: Common{
					Type:        "intrusion-set",
					ID:          isID,
					SpecVersion: "2.1",
					Created:     now,
					Modified:    now,
					Labels:      labelsForAttackType(inc.AttackType),
				},
				Name:        profile.Name,
				Description: profile.Description,
				Aliases:     profile.Aliases,
				FirstSeen:   profile.FirstSeen,
				LastSeen:    profile.LastSeen,
			})
			if campaignID != "" {
				objects = append(objects, rel(now, "attributed-to", campaignID, isID, labelsForAttackType(inc.AttackType)))
			}
			for _, ttp := range profile.TTPs {
				apID := StixID("attack-pattern", ttp.ID)
				objects = append(objects, AttackPattern{
					Common: Common{
						Type:        "attack-pattern",
						ID:          apID,
						SpecVersion: "2.1",
						Created:     now,
						Modified:    now,
						ExternalRefs: []ExternalRef{{
							SourceName: "mitre-attack",
							ExternalID: ttp.ID,
							URL:        mitreURL(ttp.ID),
						}},
					},
					Name: ttp.Name,
				})
				objects = append(objects, rel(now, "uses", isID, apID, labelsForAttackType(inc.AttackType)))
			}
		}
	}

	// Malware — derived from campaign + attack type
	var malwareID string
	if campaignID != "" {
		malwareID = StixID("malware", inc.Campaign.Name)
		mTypes := attackTypeToMalwareTypes[inc.AttackType]
		if len(mTypes) == 0 {
			mTypes = []string{"trojan"}
		}
		objects = append(objects, Malware{
			Common: Common{
				Type:        "malware",
				ID:          malwareID,
				SpecVersion: "2.1",
				Created:     now,
				Modified:    now,
				Labels:      labelsForAttackType(inc.AttackType),
			},
			Name:         inc.Campaign.Name,
			MalwareTypes: mTypes,
			IsFamily:     true,
		})
		objects = append(objects, rel(now, "uses", campaignID, malwareID, labelsForAttackType(inc.AttackType)))
	}

	// AttackPattern — one per MITRE technique
	for _, t := range inc.Hunting.MITRETechniques {
		apID := StixID("attack-pattern", t.ID)
		objects = append(objects, AttackPattern{
			Common: Common{
				Type:        "attack-pattern",
				ID:          apID,
				SpecVersion: "2.1",
				Created:     now,
				Modified:    now,
				Labels:      labelsForAttackType(inc.AttackType),
				ExternalRefs: []ExternalRef{{
					SourceName: "mitre-attack",
					ExternalID: t.ID,
					URL:        mitreURL(t.ID),
				}},
			},
			Name: t.Name,
			KillChainPhases: []KillChain{{
				KillChainName: "mitre-attack",
				PhaseName:     "initial-access",
			}},
		})
		if campaignID != "" {
			objects = append(objects, rel(now, "uses", campaignID, apID, labelsForAttackType(inc.AttackType)))
		}
	}

	// Indicator helpers
	indTypes := attackTypeToIndicatorTypes[inc.AttackType]
	if len(indTypes) == 0 {
		indTypes = []string{"malicious-activity"}
	}
	incRefs := refsFromReferences(inc.References)

	addIndicator := func(name, description, pattern string, confidence float64) {
		indID := StixID("indicator", inc.ID+":"+pattern)
		ind := Indicator{
			Common: Common{
				Type:         "indicator",
				ID:           indID,
				SpecVersion:  "2.1",
				Created:      now,
				Modified:     now,
				Confidence:   toSTIXConfidence(confidence),
				Labels:       labelsForAttackType(inc.AttackType),
				ExternalRefs: incRefs,
			},
			Name:           name,
			Description:    description,
			Pattern:        pattern,
			PatternType:    "stix",
			PatternVersion: "2.1",
			ValidFrom:      now,
			IndicatorTypes: indTypes,
		}
		objects = append(objects, ind)

		// Indicator indicates campaign, or malware if no campaign
		switch {
		case campaignID != "":
			objects = append(objects, rel(now, "indicates", indID, campaignID, labelsForAttackType(inc.AttackType)))
		case malwareID != "":
			objects = append(objects, rel(now, "indicates", indID, malwareID, labelsForAttackType(inc.AttackType)))
		}
	}

	for _, d := range inc.Indicators.Domains {
		addIndicator(
			"C2 Domain: "+d.Value,
			fmt.Sprintf("C2 domain associated with %s", inc.ID),
			DomainPattern(d.Value),
			d.Confidence,
		)
	}

	for _, ip := range inc.Indicators.IPs {
		pat := IPv4Pattern(ip.Value)
		if strings.Contains(ip.Value, ":") {
			pat = IPv6Pattern(ip.Value)
		}
		addIndicator(
			"C2 IP: "+ip.Value,
			fmt.Sprintf("C2 IP associated with %s", inc.ID),
			pat,
			ip.Confidence,
		)
	}

	for _, u := range inc.Indicators.URLs {
		addIndicator(
			"Malicious URL: "+u.Value,
			fmt.Sprintf("Malicious URL associated with %s", inc.ID),
			URLPattern(u.Value),
			u.Confidence,
		)
	}

	for _, h := range inc.Indicators.FileHashes {
		label := strings.ToUpper(h.Algorithm) + " hash"
		if h.Filename != "" {
			label += ": " + h.Filename
		}
		addIndicator(
			label,
			fmt.Sprintf("Malicious file hash associated with %s", inc.ID),
			hashPattern(h.Algorithm, h.Value),
			h.Confidence,
		)
	}

	for _, fn := range inc.Indicators.FileNames {
		addIndicator(
			"Malicious file: "+fn,
			fmt.Sprintf("Malicious filename associated with %s", inc.ID),
			FileNamePattern(fn),
			0.70,
		)
	}

	if inc.Indicators.Persistence != nil {
		for _, svc := range inc.Indicators.Persistence.ServiceNames {
			addIndicator(
				"Persistence service: "+svc,
				fmt.Sprintf("Persistence mechanism associated with %s", inc.ID),
				ServicePattern(svc),
				0.75,
			)
		}
		for _, la := range inc.Indicators.Persistence.MacOSLaunchAgent {
			addIndicator(
				"LaunchAgent: "+filepath.Base(la),
				fmt.Sprintf("macOS persistence via LaunchAgent associated with %s", inc.ID),
				FilePathPattern(la),
				0.80,
			)
		}
		for _, unit := range inc.Indicators.Persistence.LinuxSystemd {
			addIndicator(
				"Systemd unit: "+filepath.Base(unit),
				fmt.Sprintf("Linux persistence via systemd associated with %s", inc.ID),
				FilePathPattern(unit),
				0.80,
			)
		}
	}

	for _, fp := range inc.Indicators.FilePaths {
		addIndicator(
			"Malicious path: "+filepath.Base(fp),
			fmt.Sprintf("Malicious file path associated with %s", inc.ID),
			FilePathPattern(fp),
			0.70,
		)
	}

	return Bundle{
		Type:    "bundle",
		ID:      StixID("bundle", inc.ID),
		Objects: objects,
	}
}
