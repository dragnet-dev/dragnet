package incident

import "time"

// Ecosystem identifies a package registry ecosystem.
type Ecosystem string

const (
	EcosystemNPM       Ecosystem = "npm"
	EcosystemPyPI      Ecosystem = "pypi"
	EcosystemCargo     Ecosystem = "cargo"
	EcosystemMaven     Ecosystem = "maven"
	EcosystemNuGet     Ecosystem = "nuget"
	EcosystemRubyGems  Ecosystem = "rubygems"
	EcosystemGo        Ecosystem = "go"
	EcosystemHex       Ecosystem = "hex"
	EcosystemPackagist Ecosystem = "packagist"
	EcosystemPub       Ecosystem = "pub"
)

// Incident is the canonical dragnet incident record, mapped 1:1 to the YAML schema.
type Incident struct {
	ID               string           `yaml:"id" json:"id"`
	// LegacyID preserves the original source-prefixed ID (urlhaus-12345,
	// cisa-cveYYYYNNNN, ossf-...) when the canonical dragnet-{module}-YYYY-NNNN
	// ID is assigned at ingest. Kept for traceability + lookups that still
	// reference the old IDs. Omitted when ID was never rewritten.
	LegacyID         string           `yaml:"legacy_id,omitempty" json:"legacy_id,omitempty"`
	Source           string           `yaml:"source,omitempty" json:"source,omitempty"`
	OSVID            string           `yaml:"osv_id,omitempty" json:"osv_id,omitempty"`
	GHSAID           string           `yaml:"ghsa_id,omitempty" json:"ghsa_id,omitempty"`
	Packages         []Package        `yaml:"packages" json:"packages"`
	AttackType       string           `yaml:"attack_type" json:"attack_type"`
	Severity         string           `yaml:"severity" json:"severity"`
	CompromiseWindow CompromiseWindow `yaml:"compromise_window,omitempty" json:"compromise_window,omitempty"`
	Campaign         Campaign         `yaml:"campaign,omitempty" json:"campaign,omitempty"`
	Description      string           `yaml:"description" json:"description"`
	References       []string         `yaml:"references" json:"references"`
	Exposure         Exposure         `yaml:"exposure,omitempty" json:"exposure,omitempty"`
	Indicators       Indicators       `yaml:"indicators,omitempty" json:"indicators,omitempty"`
	Hunting          Hunting          `yaml:"hunting,omitempty" json:"hunting,omitempty"`
	DetectionTargets []string         `yaml:"detection_targets,omitempty" json:"detection_targets,omitempty"`

	// Domain-specific extension fields (only one is set per incident based on module)
	MalwareExt    *MalwareExtension    `yaml:"malware_ext,omitempty" json:"malware_ext,omitempty"`
	RansomwareExt *RansomwareExtension `yaml:"ransomware_ext,omitempty" json:"ransomware_ext,omitempty"`
	CVEExt        *CVEExtension        `yaml:"cve_ext,omitempty" json:"cve_ext,omitempty"`
	ContainerExt  *ContainerExtension  `yaml:"container_ext,omitempty" json:"container_ext,omitempty"`

	// All sources that reported this incident (populated by the merger when
	// multiple sources cover the same event; singular Source is the primary).
	Sources []string `yaml:"sources,omitempty" json:"sources,omitempty"`

	// Written by dragnet enrich --cross-domain
	CrossDomainLinks   []CrossDomainLink `yaml:"cross_domain_links,omitempty" json:"cross_domain_links,omitempty"`
	CrossDomainSources []string          `yaml:"cross_domain_sources,omitempty" json:"cross_domain_sources,omitempty"`

	// Written by the actor attribution pass — slugs of attributed actor profiles.
	ActorIDs []string `yaml:"actor_ids,omitempty" json:"actor_ids,omitempty"`

	// Written by dragnet sync when popularity data is available
	Impact        *IncidentImpact   `yaml:"impact,omitempty" json:"impact,omitempty"`
	TyposquatInfo *TyposquatDetails `yaml:"typosquat,omitempty" json:"typosquat,omitempty"`
}

// ── IMPACT / POPULARITY ────────────────────────────────────────────────────

// IncidentImpact captures download-count based impact data for affected packages.
type IncidentImpact struct {
	Packages              []PackageImpact `yaml:"packages,omitempty" json:"packages,omitempty"`
	OverallImpactRating   string          `yaml:"overall_impact_rating,omitempty" json:"overall_impact_rating,omitempty"`
	TotalWeeklyDownloads  int64           `yaml:"total_weekly_downloads,omitempty" json:"total_weekly_downloads,omitempty"`
	TyposquatTargetImpact string          `yaml:"typosquat_target_impact,omitempty" json:"typosquat_target_impact,omitempty"`
}

// PackageImpact records download statistics for a single affected package.
type PackageImpact struct {
	Name                string    `yaml:"name" json:"name"`
	Ecosystem           string    `yaml:"ecosystem" json:"ecosystem"`
	WeeklyDownloads     int64     `yaml:"weekly_downloads" json:"weekly_downloads"`
	MonthlyDownloads    int64     `yaml:"monthly_downloads,omitempty" json:"monthly_downloads,omitempty"`
	ImpactRating        string    `yaml:"impact_rating" json:"impact_rating"`
	EcosystemPercentile float64   `yaml:"ecosystem_percentile,omitempty" json:"ecosystem_percentile,omitempty"`
	FetchedAt           time.Time `yaml:"fetched_at" json:"fetched_at"`
}

// TyposquatDetails describes the typosquat relationship when attack_type == "typosquat".
type TyposquatDetails struct {
	NewPackage            string  `yaml:"new_package" json:"new_package"`
	TargetPackage         string  `yaml:"target_package" json:"target_package"`
	TargetWeeklyDownloads int64   `yaml:"target_weekly_downloads" json:"target_weekly_downloads"`
	TargetImpactRating    string  `yaml:"target_impact_rating" json:"target_impact_rating"`
	SimilarityScore       float64 `yaml:"similarity_score" json:"similarity_score"`
	Technique             string  `yaml:"technique" json:"technique"`
}

// ── MALWARE EXTENSION ──────────────────────────────────────────────────────

type MalwareExtension struct {
	MalwareFamily     string           `yaml:"malware_family,omitempty" json:"malware_family,omitempty"`
	MalwareType       string           `yaml:"malware_type,omitempty" json:"malware_type,omitempty"`
	TargetedSectors   []string         `yaml:"targeted_sectors,omitempty" json:"targeted_sectors,omitempty"`
	TargetedCountries []string         `yaml:"targeted_countries,omitempty" json:"targeted_countries,omitempty"`
	Platforms         []string         `yaml:"platforms,omitempty" json:"platforms,omitempty"`
	Mutexes           []IndicatorValue `yaml:"mutexes,omitempty" json:"mutexes,omitempty"`
	RegistryKeys      []IndicatorValue `yaml:"registry_keys,omitempty" json:"registry_keys,omitempty"`
	ScheduledTasks    []IndicatorValue `yaml:"scheduled_tasks,omitempty" json:"scheduled_tasks,omitempty"`
	NamedPipes        []IndicatorValue `yaml:"named_pipes,omitempty" json:"named_pipes,omitempty"`
	UserAgents        []IndicatorValue `yaml:"user_agents,omitempty" json:"user_agents,omitempty"`
	YaraRules         []YaraRule       `yaml:"yara_rules,omitempty" json:"yara_rules,omitempty"`
	Certificates      []Certificate    `yaml:"certificates,omitempty" json:"certificates,omitempty"`
}

type YaraRule struct {
	Name       string   `yaml:"name" json:"name"`
	SourceURL  string   `yaml:"source,omitempty" json:"source,omitempty"`
	Sources    []string `yaml:"sources,omitempty" json:"sources,omitempty"`
	Confidence float64  `yaml:"confidence,omitempty" json:"confidence,omitempty"`
}

type Certificate struct {
	Subject    string   `yaml:"subject,omitempty" json:"subject,omitempty"`
	Thumbprint string   `yaml:"thumbprint,omitempty" json:"thumbprint,omitempty"`
	Sources    []string `yaml:"sources,omitempty" json:"sources,omitempty"`
	Confidence float64  `yaml:"confidence,omitempty" json:"confidence,omitempty"`
}

// ── RANSOMWARE EXTENSION ───────────────────────────────────────────────────

type RansomwareExtension struct {
	RansomwareGroup         string           `yaml:"ransomware_group,omitempty" json:"ransomware_group,omitempty"`
	OperationType           string           `yaml:"operation_type,omitempty" json:"operation_type,omitempty"`
	AffiliateModel          string           `yaml:"affiliate_model,omitempty" json:"affiliate_model,omitempty"`
	TargetedSectors         []string         `yaml:"targeted_sectors,omitempty" json:"targeted_sectors,omitempty"`
	TargetedCountries       []string         `yaml:"targeted_countries,omitempty" json:"targeted_countries,omitempty"`
	RansomNoteStrings       []IndicatorValue `yaml:"ransom_note_strings,omitempty" json:"ransom_note_strings,omitempty"`
	EncryptedFileExtensions []string         `yaml:"encrypted_file_extensions,omitempty" json:"encrypted_file_extensions,omitempty"`
	RansomNoteFilenames     []string         `yaml:"ransom_note_filenames,omitempty" json:"ransom_note_filenames,omitempty"`
	ToolsObserved           []ObservedTool   `yaml:"tools_observed,omitempty" json:"tools_observed,omitempty"`
}

type ObservedTool struct {
	Name    string `yaml:"name" json:"name"`
	Version string `yaml:"version,omitempty" json:"version,omitempty"`
	Purpose string `yaml:"purpose,omitempty" json:"purpose,omitempty"`
}

// ── CVE EXTENSION ──────────────────────────────────────────────────────────

type CVEExtension struct {
	CVEID            string             `yaml:"cve_id,omitempty" json:"cve_id,omitempty"`
	CVSSScore        float64            `yaml:"cvss_score,omitempty" json:"cvss_score,omitempty"`
	CVSSVector       string             `yaml:"cvss_vector,omitempty" json:"cvss_vector,omitempty"`
	AffectedSoftware []AffectedSoftware `yaml:"affected_software,omitempty" json:"affected_software,omitempty"`
	ExploitType      string             `yaml:"exploit_type,omitempty" json:"exploit_type,omitempty"`
	PatchAvailable   bool               `yaml:"patch_available,omitempty" json:"patch_available,omitempty"`
	PatchURL         string             `yaml:"patch_url,omitempty" json:"patch_url,omitempty"`
	ExploitedInWild  bool               `yaml:"exploited_in_wild,omitempty" json:"exploited_in_wild,omitempty"`
	ExploitPublic    bool               `yaml:"exploit_public,omitempty" json:"exploit_public,omitempty"`
	HTTPIndicators   []HTTPIndicator    `yaml:"http_indicators,omitempty" json:"http_indicators,omitempty"`
}

type AffectedSoftware struct {
	Vendor           string   `yaml:"vendor,omitempty" json:"vendor,omitempty"`
	Product          string   `yaml:"product,omitempty" json:"product,omitempty"`
	VersionsAffected []string `yaml:"versions_affected,omitempty" json:"versions_affected,omitempty"`
	VersionsPatched  []string `yaml:"versions_patched,omitempty" json:"versions_patched,omitempty"`
}

type HTTPIndicator struct {
	Type       string   `yaml:"type" json:"type"`
	Value      string   `yaml:"value" json:"value"`
	Sources    []string `yaml:"sources,omitempty" json:"sources,omitempty"`
	Confidence float64  `yaml:"confidence,omitempty" json:"confidence,omitempty"`
}

// ── CONTAINER EXTENSION ───────────────────────────────────────────────────

// AffectedImage describes a Docker image tag affected by a CVE.
type AffectedImage struct {
	Repository     string   `yaml:"repository" json:"repository"`
	OSFamily       string   `yaml:"os_family,omitempty" json:"os_family,omitempty"` // alpine|debian|ubuntu|rhel|amazon
	VulnerableTags []string `yaml:"vulnerable_tags" json:"vulnerable_tags"`
	FixedTag       string   `yaml:"fixed_tag,omitempty" json:"fixed_tag,omitempty"`
	CVEIDs         []string `yaml:"cve_ids,omitempty" json:"cve_ids,omitempty"`
	Confidence     float64  `yaml:"confidence,omitempty" json:"confidence,omitempty"`
	Sources        []string `yaml:"sources,omitempty" json:"sources,omitempty"`
}

// EOLImageInfo describes a Docker image cycle that has reached end-of-life.
type EOLImageInfo struct {
	Repository  string `yaml:"repository" json:"repository"`
	Cycle       string `yaml:"cycle" json:"cycle"`              // "16", "3.9"
	EOLDate     string `yaml:"eol_date" json:"eol_date"`           // "2023-09-11"
	Replacement string `yaml:"replacement,omitempty" json:"replacement,omitempty"` // "node:20-alpine"
}

// ContainerExtension holds container vulnerability or EOL metadata.
type ContainerExtension struct {
	AffectedImages  []AffectedImage `yaml:"affected_images,omitempty" json:"affected_images,omitempty"`
	EOLImages       []EOLImageInfo  `yaml:"eol_images,omitempty" json:"eol_images,omitempty"`
	CVSS            float64         `yaml:"cvss_score,omitempty" json:"cvss_score,omitempty"`
	ExploitedInWild bool            `yaml:"exploited_in_wild,omitempty" json:"exploited_in_wild,omitempty"`
	PublicPoC       bool            `yaml:"public_poc,omitempty" json:"public_poc,omitempty"`
	Tier            int             `yaml:"tier,omitempty" json:"tier,omitempty"` // 1=KEV 2=CVSS≥9 3=CVSS≥7+PoC
}

// ── CROSS-DOMAIN LINKS ─────────────────────────────────────────────────────

type CrossDomainLink struct {
	Module       string     `yaml:"module" json:"module"`
	IncidentID   string     `yaml:"incident_id" json:"incident_id"`
	Relationship string     `yaml:"relationship" json:"relationship"`
	Actor        string     `yaml:"actor,omitempty" json:"actor,omitempty"`
	SharedIOC    *SharedIOC `yaml:"shared_ioc,omitempty" json:"shared_ioc,omitempty"`
	Confidence   float64    `yaml:"confidence,omitempty" json:"confidence,omitempty"`
}

type SharedIOC struct {
	Type  string `yaml:"type" json:"type"`
	Value string `yaml:"value" json:"value"`
}

type Package struct {
	Name             string   `yaml:"name" json:"name"`
	Ecosystem        string   `yaml:"ecosystem" json:"ecosystem"`
	AffectedVersions []string `yaml:"affected_versions,omitempty" json:"affected_versions,omitempty"`
}

type CompromiseWindow struct {
	Start string `yaml:"start,omitempty" json:"start,omitempty"`
	End   string `yaml:"end,omitempty" json:"end,omitempty"`
}

type Campaign struct {
	Name       string `yaml:"name,omitempty" json:"name,omitempty"`
	Actor      string `yaml:"actor,omitempty" json:"actor,omitempty"`
	Confidence string `yaml:"confidence,omitempty" json:"confidence,omitempty"`
}

// ── LAYER 1: EXPOSURE ──────────────────────────────────────────────────────

type Exposure struct {
	LockfileSignatures []string `yaml:"lockfile_signatures,omitempty" json:"lockfile_signatures,omitempty"`
	FilePresence       []string `yaml:"file_presence,omitempty" json:"file_presence,omitempty"`
	IDEArtifacts       []string `yaml:"ide_artifacts,omitempty" json:"ide_artifacts,omitempty"`
	Hooks              []string `yaml:"hooks,omitempty" json:"hooks,omitempty"`
	GitDependencies    []string `yaml:"git_dependencies,omitempty" json:"git_dependencies,omitempty"`
}

// ── LAYER 2: IOC HUNTING ────────────────────────────────────────────────────

type Indicators struct {
	Domains           []IndicatorValue   `yaml:"domains,omitempty" json:"domains,omitempty"`
	IPs               []IndicatorValue   `yaml:"ips,omitempty" json:"ips,omitempty"`
	URLs              []IndicatorValue   `yaml:"urls,omitempty" json:"urls,omitempty"`
	SessionNetwork    *SessionNetwork    `yaml:"session_network,omitempty" json:"session_network,omitempty"`
	FileHashes        []FileHash         `yaml:"file_hashes,omitempty" json:"file_hashes,omitempty"`
	FileNames         []string           `yaml:"file_names,omitempty" json:"file_names,omitempty"`
	FilePaths         []string           `yaml:"file_paths,omitempty" json:"file_paths,omitempty"`
	Persistence       *Persistence       `yaml:"persistence,omitempty" json:"persistence,omitempty"`
	GitIndicators      *GitIndicators      `yaml:"git_indicators,omitempty" json:"git_indicators,omitempty"`
	CredentialTargets  *CredentialTargets  `yaml:"credential_targets,omitempty" json:"credential_targets,omitempty"`
	WorkflowIndicators []WorkflowIndicator `yaml:"workflow_indicators,omitempty" json:"workflow_indicators,omitempty"`
	ModelIndicators    []ModelIndicator    `yaml:"model_indicators,omitempty" json:"model_indicators,omitempty"`
}

type IndicatorValue struct {
	Value      string   `yaml:"value" json:"value"`
	Sources    []string `yaml:"sources,omitempty" json:"sources,omitempty"`
	Confidence float64  `yaml:"confidence,omitempty" json:"confidence,omitempty"`
}

type SessionNetwork struct {
	RecipientID string   `yaml:"recipient_id,omitempty" json:"recipient_id,omitempty"`
	SeedNodes   []string `yaml:"seed_nodes,omitempty" json:"seed_nodes,omitempty"`
	FileServer  string   `yaml:"file_server,omitempty" json:"file_server,omitempty"`
}

type FileHash struct {
	Algorithm  string   `yaml:"algorithm" json:"algorithm"`
	Value      string   `yaml:"value" json:"value"`
	Filename   string   `yaml:"filename,omitempty" json:"filename,omitempty"`
	Sources    []string `yaml:"sources,omitempty" json:"sources,omitempty"`
	Confidence float64  `yaml:"confidence,omitempty" json:"confidence,omitempty"`
}

type Persistence struct {
	ServiceNames     []string `yaml:"service_names,omitempty" json:"service_names,omitempty"`
	MacOSLaunchAgent []string `yaml:"macos_launchagent,omitempty" json:"macos_launchagent,omitempty"`
	LinuxSystemd     []string `yaml:"linux_systemd,omitempty" json:"linux_systemd,omitempty"`
}

type GitIndicators struct {
	RepoDescriptions []string `yaml:"repo_descriptions,omitempty" json:"repo_descriptions,omitempty"`
	CommitMessages   []string `yaml:"commit_messages,omitempty" json:"commit_messages,omitempty"`
}

type CredentialTargets struct {
	EnvVars           []string `yaml:"env_vars,omitempty" json:"env_vars,omitempty"`
	MetadataEndpoints []string `yaml:"metadata_endpoints,omitempty" json:"metadata_endpoints,omitempty"`
	VaultTypes        []string `yaml:"vault_types,omitempty" json:"vault_types,omitempty"`
}

type WorkflowIndicator struct {
	Type       string   `yaml:"type" json:"type"` // exfil_pattern | malicious_step | env_access
	Value      string   `yaml:"value" json:"value"`
	Sources    []string `yaml:"sources,omitempty" json:"sources,omitempty"`
	Confidence float64  `yaml:"confidence,omitempty" json:"confidence,omitempty"`
}

type ModelIndicator struct {
	Type        string   `yaml:"type" json:"type"` // format_downgrade | unexpected_binary | malicious_model_card
	Filename    string   `yaml:"filename,omitempty" json:"filename,omitempty"`
	Value       string   `yaml:"value,omitempty" json:"value,omitempty"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Sources     []string `yaml:"sources,omitempty" json:"sources,omitempty"`
	Confidence  float64  `yaml:"confidence,omitempty" json:"confidence,omitempty"`
}

// ── LAYER 3: BEHAVIOURAL HUNTING ────────────────────────────────────────────

type Hunting struct {
	MITRETechniques   []MITRETechnique  `yaml:"mitre_techniques,omitempty" json:"mitre_techniques,omitempty"`
	Behaviours        []Behaviour       `yaml:"behaviours,omitempty" json:"behaviours,omitempty"`
	EvasionIndicators EvasionIndicators `yaml:"evasion_indicators,omitempty" json:"evasion_indicators,omitempty"`
}

type MITRETechnique struct {
	ID   string `yaml:"id" json:"id"`
	Name string `yaml:"name" json:"name"`
}

type Behaviour struct {
	ID              string `yaml:"id" json:"id"`
	Description     string `yaml:"description" json:"description"`
	DetectionTarget string `yaml:"detection_target" json:"detection_target"`
	Platform        string `yaml:"platform" json:"platform"`
}

type EvasionIndicators struct {
	RussianLocaleCheck bool     `yaml:"russian_locale_check,omitempty" json:"russian_locale_check,omitempty"`
	MinCPUCount        int      `yaml:"min_cpu_count,omitempty" json:"min_cpu_count,omitempty"`
	GeofencedCountries []string `yaml:"geofenced_countries,omitempty" json:"geofenced_countries,omitempty"`
}
