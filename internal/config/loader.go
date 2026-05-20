package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the parsed representation of dragnet.yaml.
type Config struct {
	Modules            map[string]ModuleConfig            `yaml:"modules"`
	CrossEnrichment    CrossEnrichConfig                  `yaml:"cross_enrichment"`
	MultiDomainSources map[string]MultiDomainSourceConfig `yaml:"multi_domain_sources,omitempty"`
}

// MultiDomainSourceConfig defines a feed that is routed to multiple modules by keyword scoring.
type MultiDomainSourceConfig struct {
	Feed          string        `yaml:"feed"`
	GlobalExclude []string      `yaml:"global_exclude,omitempty"`
	Routing       []RoutingRule `yaml:"routing"`
}

// RoutingRule maps keyword sets to a target module.
type RoutingRule struct {
	Module  string   `yaml:"module"`
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

// ModuleConfig holds per-domain settings.
type ModuleConfig struct {
	OutputDir            string             `yaml:"output_dir"`
	Sources              map[string]bool    `yaml:"sources"`
	Ecosystems           []string           `yaml:"ecosystems,omitempty"`
	Automerge            AutomergeConfig    `yaml:"automerge"`
	PopularImageThreshold int64             `yaml:"popular_image_threshold,omitempty"`
	CVSSThresholds       CVSSThresholdConfig `yaml:"cvss_thresholds,omitempty"`
}

// CVSSThresholdConfig holds per-module CVSS tier thresholds.
type CVSSThresholdConfig struct {
	Tier2 float64 `yaml:"tier2,omitempty"` // minimum CVSS for Tier 2 (default 9.0)
	Tier3 float64 `yaml:"tier3,omitempty"` // minimum CVSS for Tier 3 (default 7.0)
}

// CrossEnrichConfig controls cross-domain IOC boosting and linking.
type CrossEnrichConfig struct {
	Enabled                  bool    `yaml:"enabled"`
	ConfidenceBoostPerDomain float64 `yaml:"confidence_boost_per_domain"`
	LinkSharedActors         bool    `yaml:"link_shared_actors"`
	LinkSharedInfrastructure bool    `yaml:"link_shared_infrastructure"`
}

// AutomergeConfig defines conditions for automatic PR merge.
type AutomergeConfig struct {
	TrustedSources []string `yaml:"trusted_sources"`
	MinIOCs        int      `yaml:"min_iocs"`
	DelayMinutes   int      `yaml:"delay_minutes"`
}

// ModuleNames is the canonical ordered list of Dragnet domains.
var ModuleNames = []string{"supply", "malware", "ransomware", "cve", "container", "os-packages"}

// Load reads dragnet.yaml from path. Returns Default() if the file does not exist.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Default returns a Config that mirrors the pre-monorepo single-module behaviour.
func Default() *Config {
	return &Config{
		Modules: map[string]ModuleConfig{
			"supply": {
				OutputDir: "supply",
				Sources: map[string]bool{
					"osv": true, "ghsa": true, "ossf": true, "cisa": true,
					"npm_registry": true, "pypi": true, "cargo": true,
					"wiz": true, "socket": true, "aikido": true, "stepsecurity": true,
					"github_actions": true, "huggingface": true,
				},
				Ecosystems: []string{"npm", "pypi", "cargo", "github-actions", "huggingface"},
				Automerge: AutomergeConfig{
					TrustedSources: []string{"wiz", "socket", "aikido", "stepsecurity"},
					MinIOCs:        3,
					DelayMinutes:   60,
				},
			},
			"malware": {
				OutputDir: "malware",
				Sources: map[string]bool{
					"polyswarm": true, "dfir_report": true, "elastic_labs": true,
					"unit42": true, "red_canary": true, "talos": true,
				},
				Automerge: AutomergeConfig{
					TrustedSources: []string{"dfir_report", "elastic_labs", "unit42"},
					MinIOCs:        5,
					DelayMinutes:   120,
				},
			},
			"ransomware": {
				OutputDir: "ransomware",
				Sources: map[string]bool{
					"ransomware_live": true, "unit42": true, "secureworks": true,
					"microsoft_sec": true, "bleepingcomputer": true,
				},
				Automerge: AutomergeConfig{
					TrustedSources: []string{"unit42", "secureworks", "microsoft_sec"},
					MinIOCs:        3,
					DelayMinutes:   60,
				},
			},
			"cve": {
				OutputDir: "cve",
				Sources: map[string]bool{
					"cisa": true, "nvd": true, "msrc": true,
					"project_zero": true, "rapid7": true, "attackerkb": true,
				},
				Automerge: AutomergeConfig{
					TrustedSources: []string{"cisa", "msrc", "project_zero"},
					MinIOCs:        1,
					DelayMinutes:   30,
				},
			},
			"container": {
				OutputDir: "container",
				Sources: map[string]bool{
					"trivy_db": true, "eol_date": true,
					"cisa": true, "attackerkb": true,
				},
				PopularImageThreshold: 1_000_000,
				CVSSThresholds: CVSSThresholdConfig{
					Tier2: 9.0,
					Tier3: 7.0,
				},
				Automerge: AutomergeConfig{
					TrustedSources: []string{"trivy_db", "cisa"},
					MinIOCs:        1,
					DelayMinutes:   30,
				},
			},
			"os-packages": {
				OutputDir:  "os-packages",
				Ecosystems: []string{"debian", "ubuntu", "alpine", "rhel"},
				Sources:    map[string]bool{"osv": true},
				Automerge: AutomergeConfig{
					TrustedSources: []string{"osv"},
					MinIOCs:        1,
					DelayMinutes:   60,
				},
			},
		},
		CrossEnrichment: CrossEnrichConfig{
			Enabled:                  true,
			ConfidenceBoostPerDomain: 0.08,
			LinkSharedActors:         true,
			LinkSharedInfrastructure: true,
		},
	}
}
