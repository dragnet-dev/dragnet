package crowdstrike

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// IOCBackend produces CrowdStrike Falcon Custom IOC JSON for bulk import.
type IOCBackend struct {
	Action string // "detect" or "prevent"
}

func NewIOC(action string) *IOCBackend {
	if action == "" {
		action = "detect"
	}
	return &IOCBackend{Action: action}
}

func (b *IOCBackend) Name() string            { return "crowdstrike-ioc" }
func (b *IOCBackend) OutputExtension() string { return ".json" }

func (b *IOCBackend) Compile(sigmaYAML []byte) ([]byte, error) {
	rule, detection, err := parseSigmaIOC(sigmaYAML)
	if err != nil {
		return nil, fmt.Errorf("crowdstrike-ioc: %w", err)
	}
	out, err := buildIOCJSON(rule, detection, b.Action)
	if err != nil {
		return nil, fmt.Errorf("crowdstrike-ioc: %w", err)
	}
	return out, nil
}

type iocRule struct {
	Title       string   `yaml:"title"`
	ID          string   `yaml:"id"`
	Status      string   `yaml:"status"`
	Level       string   `yaml:"level"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
}

func parseSigmaIOC(data []byte) (*iocRule, map[string]interface{}, error) {
	var rule iocRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, nil, err
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}
	det, _ := doc["detection"].(map[string]interface{})
	return &rule, det, nil
}

// Falcon IOC severity mapping
var iocSeverity = map[string]string{
	"critical": "HIGH",
	"high":     "HIGH",
	"medium":   "MEDIUM",
	"low":      "LOW",
}

type falconIOC struct {
	Type        string   `json:"type"`
	Value       string   `json:"value"`
	Action      string   `json:"action"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Source      string   `json:"source"`
	Platforms   []string `json:"platforms"`
}

func buildIOCJSON(rule *iocRule, detection map[string]interface{}, action string) ([]byte, error) {
	severity := iocSeverity[strings.ToLower(rule.Level)]
	if severity == "" {
		severity = "MEDIUM"
	}

	// Build tags from Sigma tags (ecosystem + MITRE)
	tags := []string{"supply-chain"}
	for _, tag := range rule.Tags {
		lower := strings.ToLower(tag)
		if strings.HasPrefix(lower, "attack.t") {
			tags = append(tags, strings.TrimPrefix(lower, "attack."))
		}
	}

	desc := fmt.Sprintf("Dragnet: %s | ID: %s | Status: %s", rule.Title, rule.ID, rule.Status)

	var iocs []falconIOC

	detKeys := make([]string, 0, len(detection))
	for k := range detection {
		detKeys = append(detKeys, k)
	}
	sort.Strings(detKeys)

	for _, k := range detKeys {
		v := detection[k]
		if k == "condition" {
			continue
		}
		sel, ok := toStringMapIOC(v)
		if !ok {
			continue
		}
		selKeys := make([]string, 0, len(sel))
		for fk := range sel {
			selKeys = append(selKeys, fk)
		}
		sort.Strings(selKeys)
		for _, fieldKey := range selKeys {
			fieldVal := sel[fieldKey]
			field := strings.ToLower(strings.Split(fieldKey, "|")[0])
			vals := toStringSliceIOC(fieldVal)

			switch field {
			case "destinationhostname":
				for _, val := range vals {
					iocs = append(iocs, falconIOC{
						Type:        "domain",
						Value:       val,
						Action:      action,
						Severity:    severity,
						Description: desc,
						Tags:        tags,
						Source:      "Dragnet",
						Platforms:   []string{"windows", "mac", "linux"},
					})
				}
			case "destinationip":
				for _, val := range vals {
					iocType := "ipv4"
					if strings.Contains(val, ":") {
						iocType = "ipv6"
					}
					iocs = append(iocs, falconIOC{
						Type:        iocType,
						Value:       val,
						Action:      action,
						Severity:    severity,
						Description: desc,
						Tags:        tags,
						Source:      "Dragnet",
						Platforms:   []string{"windows", "mac", "linux"},
					})
				}
			case "hashes":
				for _, val := range vals {
					parts := strings.SplitN(val, "=", 2)
					if len(parts) != 2 {
						continue
					}
					algo := strings.ToLower(parts[0])
					hash := parts[1]
					// Falcon supports md5 and sha256 only
					if algo != "md5" && algo != "sha256" {
						continue
					}
					iocs = append(iocs, falconIOC{
						Type:        algo,
						Value:       strings.ToLower(hash),
						Action:      action,
						Severity:    severity,
						Description: desc,
						Tags:        tags,
						Source:      "Dragnet",
						Platforms:   []string{"windows", "mac", "linux"},
					})
				}
			}
		}
	}

	if len(iocs) == 0 {
		// Return empty array — no extractable IOCs (e.g. behavioural hunting rules)
		return []byte("[]\n"), nil
	}

	return json.MarshalIndent(iocs, "", "  ")
}

func toStringMapIOC(v interface{}) (map[string]interface{}, bool) {
	switch m := v.(type) {
	case map[string]interface{}:
		return m, true
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(m))
		for k, val := range m {
			out[fmt.Sprintf("%v", k)] = val
		}
		return out, true
	}
	return nil, false
}

func toStringSliceIOC(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, item := range val {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	}
	return nil
}
