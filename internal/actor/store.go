package actor

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"gopkg.in/yaml.v3"
)

// Store is an in-memory lookup table of actor profiles keyed by slug and all aliases.
type Store struct {
	profiles map[string]*ActorProfile // slug → profile
	aliases  map[string]string        // lowercase alias/name → slug
	trie     *ahocorasick.Trie        // multi-pattern matcher for long aliases (len ≥ minAliasLen)
	acSlugs  []string                 // parallel to trie patterns: acSlugs[i] → slug
	shortRe  *regexp.Regexp           // word-boundary OR-join of short aliases (len < minAliasLen)
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
	s.trie, s.acSlugs, s.shortRe = buildSearchStructures(s.aliases)
	return s
}

// buildSearchStructures compiles an Aho-Corasick trie for long aliases and a
// word-boundary regex for short ones. Both are built once at store-load time.
func buildSearchStructures(aliases map[string]string) (*ahocorasick.Trie, []string, *regexp.Regexp) {
	var longPatterns []string
	var longSlugs []string
	var shortAliases []string

	for alias, slug := range aliases {
		if len(alias) >= minAliasLen {
			longPatterns = append(longPatterns, alias)
			longSlugs = append(longSlugs, slug)
		} else if alias != "" {
			shortAliases = append(shortAliases, regexp.QuoteMeta(alias))
		}
	}

	var trie *ahocorasick.Trie
	if len(longPatterns) > 0 {
		trie = ahocorasick.NewTrieBuilder().AddStrings(longPatterns).Build()
	}

	var shortRe *regexp.Regexp
	if len(shortAliases) > 0 {
		shortRe = regexp.MustCompile(`(?i)\b(` + strings.Join(shortAliases, `|`) + `)\b`)
	}

	return trie, longSlugs, shortRe
}

// LookupByID finds an actor profile by its canonical slug (e.g. "apt28").
func (s *Store) LookupByID(id string) (*ActorProfile, bool) {
	p, ok := s.profiles[id]
	return p, ok
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

// MergeLinkedIncidents copies accumulated LinkedIncidents and AggregatedIOCs
// from an on-disk store into a slice of fresh profiles, preserving attribution
// history across MITRE bundle updates.
func MergeLinkedIncidents(fresh []*ActorProfile, disk *Store) {
	if disk == nil {
		return
	}
	for _, p := range fresh {
		old, ok := disk.profiles[p.ID]
		if !ok {
			continue
		}
		for _, link := range old.LinkedIncidents {
			if !hasLink(p, link.IncidentID) {
				p.LinkedIncidents = append(p.LinkedIncidents, link)
			}
		}
		mergeAggregatedIOCs(p, old)
	}
}

func mergeAggregatedIOCs(dst, src *ActorProfile) {
	domainSet := toSet(dst.AggregatedIOCs.Domains)
	for _, d := range src.AggregatedIOCs.Domains {
		if !domainSet[d] {
			domainSet[d] = true
			dst.AggregatedIOCs.Domains = append(dst.AggregatedIOCs.Domains, d)
		}
	}
	ipSet := toSet(dst.AggregatedIOCs.IPs)
	for _, ip := range src.AggregatedIOCs.IPs {
		if !ipSet[ip] {
			ipSet[ip] = true
			dst.AggregatedIOCs.IPs = append(dst.AggregatedIOCs.IPs, ip)
		}
	}
	hashSet := toSet(dst.AggregatedIOCs.Hashes)
	for _, h := range src.AggregatedIOCs.Hashes {
		if !hashSet[h] {
			hashSet[h] = true
			dst.AggregatedIOCs.Hashes = append(dst.AggregatedIOCs.Hashes, h)
		}
	}
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
