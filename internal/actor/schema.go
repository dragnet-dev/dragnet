package actor

// ActorProfile is the canonical representation of a threat actor, seeded from
// the MITRE ATT&CK intrusion-set objects and enriched by the attribution pass.
type ActorProfile struct {
	ID          string   `yaml:"id"`                   // slug: apt28
	Name        string   `yaml:"name"`
	MITREID     string   `yaml:"mitre_id,omitempty"`   // G0007
	Aliases     []string `yaml:"aliases,omitempty"`
	Type        string   `yaml:"type"`                 // nation-state | criminal | hacktivist | unknown
	Description string   `yaml:"description,omitempty"`
	TTPs        []TTP    `yaml:"ttps,omitempty"`
	Software    []string `yaml:"software,omitempty"`
	FirstSeen   string   `yaml:"first_seen,omitempty"`
	LastSeen    string   `yaml:"last_seen,omitempty"`

	// Written by attribution pass each sync run.
	LinkedIncidents []IncidentLink `yaml:"incidents,omitempty"`
	AggregatedIOCs  AggregatedIOCs `yaml:"iocs,omitempty"`
	Confidence      string         `yaml:"confidence"` // high | medium | low
}

// TTP is a single MITRE ATT&CK technique used by this actor.
type TTP struct {
	ID   string `yaml:"id"`   // T1566.001
	Name string `yaml:"name"`
}

// IncidentLink records a Dragnet incident attributed to this actor.
type IncidentLink struct {
	IncidentID string  `yaml:"id"`
	Module     string  `yaml:"module"`
	MatchType  string  `yaml:"match_type"` // explicit | inferred
	Confidence float64 `yaml:"confidence"`
}

// AggregatedIOCs is the union of network/file indicators across all linked incidents.
type AggregatedIOCs struct {
	Domains []string `yaml:"domains,omitempty"`
	IPs     []string `yaml:"ips,omitempty"`
	Hashes  []string `yaml:"hashes,omitempty"`
}
