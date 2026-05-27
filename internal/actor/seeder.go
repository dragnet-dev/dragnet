package actor

import (
	"embed"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed seeds/*.yaml
var seedFS embed.FS

// SeedProfiles writes embedded supply-chain actor profiles to profileDir if
// they don't already exist on disk. Existing files are never overwritten so
// haul's live data always takes precedence over the binary's defaults.
func SeedProfiles(profileDir string) error {
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		return err
	}

	entries, err := seedFS.ReadDir("seeds")
	if err != nil {
		return err
	}

	seeded := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		dest := filepath.Join(profileDir, e.Name())
		if _, err := os.Stat(dest); err == nil {
			continue // already exists — haul's copy wins
		}

		data, err := seedFS.ReadFile("seeds/" + e.Name())
		if err != nil {
			log.Printf("[actor] seed: read %s: %v", e.Name(), err)
			continue
		}

		// Validate the YAML before writing so a corrupt embed doesn't clobber
		// an otherwise healthy profiles directory.
		var p ActorProfile
		if err := yaml.Unmarshal(data, &p); err != nil {
			log.Printf("[actor] seed: invalid YAML %s: %v", e.Name(), err)
			continue
		}

		if err := os.WriteFile(dest, data, 0o644); err != nil {
			log.Printf("[actor] seed: write %s: %v", dest, err)
			continue
		}
		seeded++
	}
	if seeded > 0 {
		log.Printf("[actor] seeded %d supply-chain actor profile(s) to %s", seeded, profileDir)
	}
	return nil
}

// ApplySeeds loads all embedded seed profiles and adds any that are not
// already present in s (by slug). This ensures seeded actors participate in
// attribution even on fresh MITRE fetches that don't read from disk.
func ApplySeeds(s *Store) {
	entries, err := seedFS.ReadDir("seeds")
	if err != nil {
		return
	}
	added := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := seedFS.ReadFile("seeds/" + e.Name())
		if err != nil {
			continue
		}
		var p ActorProfile
		if err := yaml.Unmarshal(data, &p); err != nil || p.ID == "" {
			continue
		}
		// Skip if the store already has this slug (haul's version takes precedence).
		if _, ok := s.profiles[p.ID]; ok {
			continue
		}
		s.profiles[p.ID] = &p
		s.aliases[strings.ToLower(p.Name)] = p.ID
		for _, a := range p.Aliases {
			if strings.TrimSpace(a) != "" {
				s.aliases[strings.ToLower(a)] = p.ID
			}
		}
		added++
	}
	if added > 0 {
		log.Printf("[actor] applied %d embedded supply-chain actor seed(s)", added)
	}
}
