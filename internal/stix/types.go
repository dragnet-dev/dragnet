package stix

import "time"

// Common holds properties shared by all STIX domain objects.
type Common struct {
	Type         string        `json:"type"`
	ID           string        `json:"id"`
	SpecVersion  string        `json:"spec_version"`
	Created      time.Time     `json:"created"`
	Modified     time.Time     `json:"modified"`
	Confidence   int           `json:"confidence,omitempty"`
	Labels       []string      `json:"labels,omitempty"`
	ExternalRefs []ExternalRef `json:"external_references,omitempty"`
}

// ExternalRef links a STIX object to an external source or identifier.
type ExternalRef struct {
	SourceName string `json:"source_name"`
	URL        string `json:"url,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
}

// KillChain represents a kill chain phase (e.g. MITRE ATT&CK tactic).
type KillChain struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// Bundle is the STIX 2.1 container for all objects.
type Bundle struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Objects []any  `json:"objects"`
}

// Identity represents Dragnet as the intelligence source.
type Identity struct {
	Common
	Name          string `json:"name"`
	IdentityClass string `json:"identity_class"`
	Description   string `json:"description,omitempty"`
}

// Indicator represents an IOC with a STIX pattern expression.
type Indicator struct {
	Common
	Name            string      `json:"name"`
	Description     string      `json:"description,omitempty"`
	Pattern         string      `json:"pattern"`
	PatternType     string      `json:"pattern_type"`
	PatternVersion  string      `json:"pattern_version"`
	ValidFrom       time.Time   `json:"valid_from"`
	IndicatorTypes  []string    `json:"indicator_types"`
	KillChainPhases []KillChain `json:"kill_chain_phases,omitempty"`
}

// Malware represents the malicious payload or family.
type Malware struct {
	Common
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	MalwareTypes []string `json:"malware_types"`
	IsFamily     bool     `json:"is_family"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// ThreatActor represents the group or individual behind a campaign.
type ThreatActor struct {
	Common
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	ThreatActorTypes []string `json:"threat_actor_types"`
	Sophistication   string   `json:"sophistication,omitempty"`
	Aliases          []string `json:"aliases,omitempty"`
}

// Campaign represents the named operation.
type Campaign struct {
	Common
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	FirstSeen   *time.Time `json:"first_seen,omitempty"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
	Objective   string     `json:"objective,omitempty"`
}

// AttackPattern represents a MITRE ATT&CK technique.
type AttackPattern struct {
	Common
	Name            string      `json:"name"`
	Description     string      `json:"description,omitempty"`
	KillChainPhases []KillChain `json:"kill_chain_phases,omitempty"`
}

// Vulnerability represents a known CVE/OSV/GHSA.
type Vulnerability struct {
	Common
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// IntrusionSet represents a named set of adversary activity (ATT&CK group).
type IntrusionSet struct {
	Common
	Name              string   `json:"name"`
	Description       string   `json:"description,omitempty"`
	Aliases           []string `json:"aliases,omitempty"`
	Goals             []string `json:"goals,omitempty"`
	ResourceLevel     string   `json:"resource_level,omitempty"`
	PrimaryMotivation string   `json:"primary_motivation,omitempty"`
	FirstSeen         string   `json:"first_seen,omitempty"`
	LastSeen          string   `json:"last_seen,omitempty"`
}

// Relationship is a directed edge linking two STIX objects.
type Relationship struct {
	Common
	RelationshipType string `json:"relationship_type"`
	SourceRef        string `json:"source_ref"`
	TargetRef        string `json:"target_ref"`
	Description      string `json:"description,omitempty"`
}
