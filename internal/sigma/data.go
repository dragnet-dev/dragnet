package sigma

// TemplateData holds all values passed into a Sigma rule template.
type TemplateData struct {
	ID         string // Sigma rule UUID
	DragnetID  string // clean sequential ID: dragnet-supply-2026-0001
	IncidentID string // internal source-prefixed ID, kept as cross-reference
	Year       string // YYYY, used for output subdir routing (not in templates)
	Module     string // supply | malware | ransomware | cve | container
	Title      string
	Status     string // stable/test/experimental from confidence.Status()
	Description string
	Date        string // YYYY-MM-DD
	References  []string
	Level       string   // critical/high/medium/low (from incident severity)
	Tags        []string // MITRE ATT&CK tags like "attack.t1195.002"

	// Layer 1 — Exposure
	LockfileSignatures []string
	FilePresence       []string
	IDEArtifacts       []string
	Hooks              []string

	// Layer 2 — IOC
	Domains    []IOCValue
	IPs        []IOCValue
	URLs       []IOCValue
	FileHashes []HashValue

	// Persistence
	ServiceNames     []string
	MacOSPersistence []string
	LinuxPersistence []string

	// Session network
	SessionRecipientID string
	SessionSeedNodes   []string
	SessionFileServer  string

	// Layer 3 — Hunting
	Behaviour    BehaviourData
	Ecosystems   []string // package ecosystems
	PackageNames []string

	// Malware-module template fields
	MalwareFamily  string
	MalwareType    string
	Mutexes        []string
	RegistryKeys   []string
	ScheduledTasks []string
	NamedPipes     []string

	// Ransomware-module template fields
	RansomwareGroup     string
	RansomNoteFilenames []string
	ToolNames           []string // observed exfil/attack tools

	// CVE-module template fields
	CVEID          string
	CVSSScore      float64
	HTTPUserAgents []string
	HTTPPatterns   []string // URL patterns and body patterns

	// Container-module template fields
	AffectedImages []ContainerImageTmplData
	EOLImages      []EOLImageTmplData
	ContainerCVSS  float64
	ContainerTier  int

	// Supply-module: GitHub Actions template fields
	WorkflowIndicators []WorkflowIndicatorTmplData
	ActionName         string

	// Supply-module: Hugging Face template fields
	ModelIndicators []ModelIndicatorTmplData
	ModelName       string
}

// ContainerImageTmplData holds one affected image entry for template rendering.
type ContainerImageTmplData struct {
	Repository     string
	OSFamily       string
	VulnerableTags []string
	FixedTag       string
}

// EOLImageTmplData holds one end-of-life image cycle for template rendering.
type EOLImageTmplData struct {
	Repository  string
	Cycle       string
	EOLDate     string
	Replacement string
}

// IOCValue wraps a network indicator with its confidence score.
type IOCValue struct {
	Value      string
	Confidence float64
}

// HashValue wraps a file hash indicator with metadata.
type HashValue struct {
	Algorithm  string
	Value      string
	Filename   string
	Confidence float64
}

// WorkflowIndicatorTmplData holds one CI workflow indicator for template rendering.
type WorkflowIndicatorTmplData struct {
	Type  string
	Value string
}

// ModelIndicatorTmplData holds one ML model indicator for template rendering.
type ModelIndicatorTmplData struct {
	Type        string
	Filename    string
	Description string
}

// BehaviourData carries per-behaviour metadata for hunting rules.
type BehaviourData struct {
	ID          string
	Description string
	Platform    string
}
