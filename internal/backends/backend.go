package backends

// Backend compiles a Sigma rule YAML into a platform-specific detection rule.
type Backend interface {
	Name() string
	OutputExtension() string
	Compile(sigmaYAML []byte) ([]byte, error)
}
