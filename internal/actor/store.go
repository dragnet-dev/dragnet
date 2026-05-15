package actor

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Store is an in-memory lookup table of actor profiles keyed by slug and all aliases.
type Store struct {
	profiles map[string]*ActorProfile // slug → profile
	aliases  map[string]string        // lowercase alias/name → slug
}

// Load builds a Store from a slice of profiles (output of the MITRE client).
func Load(profiles []*ActorProfile) *Store {
	s := &Store{
		profiles: make(map[string]*ActorProfile, len(profiles)),
		aliases:  make(map[string]string, len(profiles)*5),
	}
	for _, p := range profiles {
		s.profiles[p.ID] = p
		s.aliases[strings.ToLower(p.Name)] = p.ID
		for _, a := range p.Aliases {
			s.aliases[strings.ToLower(a)] = p.ID
		}
	}
	return s
}

// Lookup finds an actor profile by any alias or canonical name (case-insensitive).
func (s *Store) Lookup(name string) (*ActorProfile, bool) {
	slug, ok := s.aliases[strings.ToLower(name)]
	if !ok {
		return nil, false
	}
	p, ok := s.profiles[slug]
	return p, ok
}

// Profiles returns all actor profiles in the store.
func (s *Store) Profiles() []*ActorProfile {
	out := make([]*ActorProfile, 0, len(s.profiles))
	for _, p := range s.profiles {
		out = append(out, p)
	}
	return out
}

// WriteProfiles writes all actor YAML files to outputDir and an index.yaml
// mapping every lowercase alias to its profile slug.
func (s *Store) WriteProfiles(outputDir string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}

	// Write per-actor YAML.
	for slug, p := range s.profiles {
		data, err := yaml.Marshal(p)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(outputDir, slug+".yaml"), data, 0o644); err != nil {
			return err
		}
	}

	// Write alias index.
	index := make(map[string]string, len(s.aliases))
	for alias, slug := range s.aliases {
		index[alias] = slug
	}
	idxData, err := yaml.Marshal(index)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(filepath.Dir(outputDir), "index.yaml"), idxData, 0o644)
}

// ReadProfiles loads actor YAML files from outputDir into a Store.
// Missing directory returns an empty store without error.
func ReadProfiles(outputDir string) (*Store, error) {
	entries, err := os.ReadDir(outputDir)
	if os.IsNotExist(err) {
		return Load(nil), nil
	}
	if err != nil {
		return nil, err
	}

	var profiles []*ActorProfile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(outputDir, e.Name()))
		if err != nil {
			continue
		}
		var p ActorProfile
		if err := yaml.Unmarshal(data, &p); err != nil {
			continue
		}
		profiles = append(profiles, &p)
	}
	return Load(profiles), nil
}
