package wazuh

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dragnet-dev/dragnet/internal/backends/sigma"
)

type Backend struct{}

func New() *Backend { return &Backend{} }

func (b *Backend) Name() string            { return "wazuh" }
func (b *Backend) OutputExtension() string { return ".xml" }

func (b *Backend) Compile(sigmaYAML []byte) ([]byte, error) {
	rule, detection, err := parseSigma(sigmaYAML)
	if err != nil {
		return nil, fmt.Errorf("wazuh: %w", err)
	}
	out, err := buildXML(rule, detection)
	if err != nil {
		return nil, fmt.Errorf("wazuh: %w", err)
	}
	return out, nil
}

// ---- Sigma parser ----

type sigmaRule struct {
	Title       string    `yaml:"title"`
	ID          string    `yaml:"id"`
	Status      string    `yaml:"status"`
	Level       string    `yaml:"level"`
	Description string    `yaml:"description"`
	LogSource   logSource `yaml:"logsource"`
	Tags        []string  `yaml:"tags"`
}

type logSource struct {
	Category string `yaml:"category"`
}

func parseSigma(data []byte) (*sigmaRule, map[string]interface{}, error) {
	var rule sigmaRule
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

// ---- level mapping ----

var levelMap = map[string]int{
	"critical": 12,
	"high":     10,
	"medium":   8,
	"low":      5,
}

// Sigma field → Wazuh field name
var fieldMap = map[string]string{
	"DestinationHostname": "network.destination.hostname",
	"DestinationIp":       "network.destination.ip",
	"Image":               "process.name",
	"ParentImage":         "process.parent.name",
	"CommandLine":         "process.args",
	"TargetFilename":      "file.path",
	"TargetImage":         "file.path",
	"SourceImage":         "process.name",
}

// ---- XML types ----

type xmlGroup struct {
	XMLName xml.Name  `xml:"group"`
	Name    string    `xml:"name,attr"`
	Comment string    `xml:",comment"`
	Rules   []xmlRule `xml:"rule"`
}

type xmlRule struct {
	ID          string     `xml:"id,attr"`
	Level       int        `xml:"level,attr"`
	Description string     `xml:"description"`
	Fields      []xmlField `xml:"field"`
	Options     string     `xml:"options,omitempty"`
	MITRE       *xmlMITRE  `xml:"mitre,omitempty"`
}

type xmlField struct {
	Name  string `xml:"name,attr"`
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

type xmlMITRE struct {
	IDs []string `xml:"id"`
}

// ---- builder ----

func buildXML(rule *sigmaRule, detection map[string]interface{}) ([]byte, error) {
	level := levelMap[strings.ToLower(rule.Level)]
	if level == 0 {
		level = 8
	}

	// Derive a stable 6-digit rule ID from the Sigma UUID.
	ruleID := deriveRuleID(rule.ID)

	fields := extractFields(detection)

	// Extract MITRE technique IDs from tags.
	var mitreTIDs []string
	for _, tag := range rule.Tags {
		tag = strings.ToLower(tag)
		if strings.HasPrefix(tag, "attack.t") {
			tid := strings.TrimPrefix(tag, "attack.")
			mitreTIDs = append(mitreTIDs, strings.ToUpper(tid))
		}
	}

	xr := xmlRule{
		ID:          ruleID,
		Level:       level,
		Description: rule.Title,
		Fields:      fields,
	}
	if len(mitreTIDs) > 0 {
		xr.MITRE = &xmlMITRE{IDs: mitreTIDs}
	}

	group := xmlGroup{
		Name:    "dragnet,supply_chain",
		Comment: fmt.Sprintf(" %s | Status: %s | Sigma ID: %s ", rule.Title, rule.Status, rule.ID),
		Rules:   []xmlRule{xr},
	}

	out, err := xml.MarshalIndent(group, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

func extractFields(detection map[string]interface{}) []xmlField {
	// Sort detection keys for deterministic output.
	detKeys := make([]string, 0, len(detection))
	for k := range detection {
		detKeys = append(detKeys, k)
	}
	sort.Strings(detKeys)

	var fields []xmlField
	for _, rawKey := range detKeys {
		rawVal := detection[rawKey]
		if rawKey == "condition" {
			continue
		}
		sel, ok := sigma.ToStringMap(rawVal)
		if !ok {
			continue
		}
		// Sort field keys within each selection for deterministic output.
		selKeys := make([]string, 0, len(sel))
		for k := range sel {
			selKeys = append(selKeys, k)
		}
		sort.Strings(selKeys)
		for _, fieldKey := range selKeys {
			fieldVal := sel[fieldKey]
			sigmaField, modifier := sigma.ParseField(fieldKey)

			if strings.EqualFold(sigmaField, "Hashes") {
				for _, v := range sigma.ToStringSlice(fieldVal) {
					parts := strings.SplitN(v, "=", 2)
					if len(parts) == 2 {
						fields = append(fields, xmlField{
							Name:  "file.hash." + strings.ToLower(parts[0]),
							Type:  "pcre2",
							Value: regexp.QuoteMeta(parts[1]),
						})
					}
				}
				continue
			}

			col := fieldMap[sigmaField]
			if col == "" {
				col = sigmaField
			}

			vals := sigma.ToStringSlice(fieldVal)
			if len(vals) == 0 {
				continue
			}

			pattern := buildPattern(modifier, vals)
			fields = append(fields, xmlField{Name: col, Type: "pcre2", Value: pattern})
		}
	}
	return fields
}

func buildPattern(modifier string, vals []string) string {
	escaped := make([]string, len(vals))
	for i, v := range vals {
		escaped[i] = regexp.QuoteMeta(v)
	}
	switch strings.ToLower(modifier) {
	case "contains":
		return strings.Join(escaped, "|")
	case "startswith":
		parts := make([]string, len(escaped))
		for i, e := range escaped {
			parts[i] = "^" + e
		}
		return strings.Join(parts, "|")
	case "endswith":
		parts := make([]string, len(escaped))
		for i, e := range escaped {
			parts[i] = e + "$"
		}
		return strings.Join(parts, "|")
	default:
		// Exact match
		parts := make([]string, len(escaped))
		for i, e := range escaped {
			parts[i] = "^" + e + "$"
		}
		return strings.Join(parts, "|")
	}
}

// deriveRuleID produces a 6-digit numeric string from a UUID.
func deriveRuleID(sigmaID string) string {
	if sigmaID == "" {
		return "200000"
	}
	clean := strings.ReplaceAll(sigmaID, "-", "")
	var n uint64
	for _, c := range clean {
		if c >= '0' && c <= '9' {
			n = n*10 + uint64(c-'0')
		} else if c >= 'a' && c <= 'f' {
			n = n*16 + uint64(c-'a'+10)
		}
		if n > 999999 {
			break
		}
	}
	id := n%900000 + 100000 // keep in [100000, 999999]
	return fmt.Sprintf("%d", id)
}

