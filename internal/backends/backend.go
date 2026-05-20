package backends

import "github.com/dragnet-dev/dragnet/internal/incident"

// Backend compiles a Sigma rule YAML into a platform-specific detection rule.
type Backend interface {
	Name() string
	OutputExtension() string
	Compile(sigmaYAML []byte) ([]byte, error)
}

// IOCNativeBackend generates detection content directly from incident data,
// not from compiled Sigma YAML. YARA is the canonical example.
type IOCNativeBackend interface {
	Name() string
	OutputExtension() string
	GenerateFromIncident(inc *incident.Incident) ([]byte, error)
}
