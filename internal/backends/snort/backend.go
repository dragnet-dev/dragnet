package snort

import (
	"encoding/binary"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Backend compiles Sigma network rules to Snort 3 IDS rules.
// Non-network rules emit a comment placeholder.
type Backend struct{}

func New() *Backend { return &Backend{} }

func (b *Backend) Name() string            { return "snort" }
func (b *Backend) OutputExtension() string { return ".rules" }

func (b *Backend) Compile(sigmaYAML []byte) ([]byte, error) {
	rule, detection, err := parseSigma(sigmaYAML)
	if err != nil {
		return nil, fmt.Errorf("snort: %w", err)
	}
	out, err := buildRules(rule, detection)
	if err != nil {
		return nil, fmt.Errorf("snort: %w", err)
	}
	return []byte(out), nil
}

type sigmaRule struct {
	Title     string    `yaml:"title"`
	ID        string    `yaml:"id"`
	Status    string    `yaml:"status"`
	Level     string    `yaml:"level"`
	LogSource logSource `yaml:"logsource"`
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

var classtype = map[string]string{
	"critical": "trojan-activity",
	"high":     "trojan-activity",
	"medium":   "suspicious-activity",
	"low":      "policy-violation",
}

func buildRules(rule *sigmaRule, detection map[string]interface{}) (string, error) {
	ct := classtype[strings.ToLower(rule.Level)]
	if ct == "" {
		ct = "suspicious-activity"
	}

	category := strings.ToLower(rule.LogSource.Category)
	if category != "network_connection" && category != "dns_query" {
		return fmt.Sprintf(
			"# Snort: rule %q (ID: %s) targets %q — no network rule generated\n",
			rule.Title, rule.ID, rule.LogSource.Category,
		), nil
	}

	baseSID := deriveSID(rule.ID)

	var domains, ips []string
	for k, v := range detection {
		if k == "condition" {
			continue
		}
		sel, ok := toStringMap(v)
		if !ok {
			continue
		}
		for fieldKey, fieldVal := range sel {
			field := strings.ToLower(strings.Split(fieldKey, "|")[0])
			vals := toStringSlice(fieldVal)
			switch field {
			case "destinationhostname":
				domains = append(domains, vals...)
			case "destinationip":
				ips = append(ips, vals...)
			}
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# %s\n", rule.Title))
	sb.WriteString(fmt.Sprintf("# Status: %s | Level: %s | ID: %s\n", rule.Status, rule.Level, rule.ID))

	sidCounter := baseSID
	for _, domain := range domains {
		// Snort uses content match in TCP/UDP payload for DNS hostname detection.
		sb.WriteString(fmt.Sprintf(
			`alert tcp any any -> any any (msg:"%s [%s]"; content:"%s"; nocase; classtype:%s; sid:%d; rev:1;)`+"\n",
			rule.Title, domain, domain, ct, sidCounter,
		))
		sidCounter++
		sb.WriteString(fmt.Sprintf(
			`alert udp any any -> any 53 (msg:"%s DNS [%s]"; content:"%s"; nocase; classtype:%s; sid:%d; rev:1;)`+"\n",
			rule.Title, domain, domain, ct, sidCounter,
		))
		sidCounter++
	}
	for _, ip := range ips {
		sb.WriteString(fmt.Sprintf(
			`alert ip any any -> %s any (msg:"%s [%s]"; classtype:%s; sid:%d; rev:1;)`+"\n",
			ip, rule.Title, ip, ct, sidCounter,
		))
		sidCounter++
	}

	if len(domains) == 0 && len(ips) == 0 {
		sb.WriteString(fmt.Sprintf("# No network indicators found in detection block for %s\n", rule.ID))
	}

	return sb.String(), nil
}

// deriveSID generates a stable 7-digit SID from a Sigma rule UUID.
func deriveSID(sigmaID string) uint32 {
	clean := strings.ReplaceAll(sigmaID, "-", "")
	if len(clean) < 8 {
		return 9000001
	}
	b := make([]byte, 4)
	for i := 0; i < 8 && i < len(clean); i += 2 {
		hi := hexVal(clean[i])
		lo := hexVal(clean[i+1])
		b[i/2] = hi<<4 | lo
	}
	n := binary.BigEndian.Uint32(b)
	return n%9000000 + 1000000
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func toStringMap(v interface{}) (map[string]interface{}, bool) {
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

func toStringSlice(v interface{}) []string {
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
