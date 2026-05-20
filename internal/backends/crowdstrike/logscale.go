package crowdstrike

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// LogScaleBackend compiles Sigma rules to CrowdStrike NG-SIEM (LogScale) queries.
type LogScaleBackend struct{}

func NewLogScale() *LogScaleBackend { return &LogScaleBackend{} }

func (b *LogScaleBackend) Name() string            { return "crowdstrike" }
func (b *LogScaleBackend) OutputExtension() string { return ".lqs" }

func (b *LogScaleBackend) Compile(sigmaYAML []byte) ([]byte, error) {
	rule, detection, err := parseSigmaLS(sigmaYAML)
	if err != nil {
		return nil, fmt.Errorf("logscale: %w", err)
	}
	out, err := buildLogScale(rule, detection)
	if err != nil {
		return nil, fmt.Errorf("logscale: %w", err)
	}
	return []byte(out), nil
}

type lsRule struct {
	Title     string      `yaml:"title"`
	ID        string      `yaml:"id"`
	Status    string      `yaml:"status"`
	Level     string      `yaml:"level"`
	LogSource lsLogSource `yaml:"logsource"`
}

type lsLogSource struct {
	Category string `yaml:"category"`
}

func parseSigmaLS(data []byte) (*lsRule, map[string]interface{}, error) {
	var rule lsRule
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

// Sigma field → LogScale field (Falcon telemetry schema)
var lsFieldMap = map[string]string{
	"DestinationHostname": "DomainName",
	"DestinationIp":       "RemoteAddressIP4",
	"Image":               "ImageFileName",
	"ParentImage":         "ParentImageFileName",
	"CommandLine":         "CommandLine",
	"TargetFilename":      "FilePath",
	"TargetImage":         "FilePath",
	"SourceImage":         "ImageFileName",
}

// LogScale event dataset per logsource category
var lsDataset = map[string]string{
	"network_connection": "#event_simpleName=NetworkConnectIP4",
	"dns_query":          "#event_simpleName=DnsRequest",
	"file_event":         "#event_simpleName=PeFileWritten OR #event_simpleName=NewExecutableWritten",
	"process_creation":   "#event_simpleName=ProcessRollup2",
	"process_access":     "#event_simpleName=ProcessRollup2",
}

func buildLogScale(rule *lsRule, detection map[string]interface{}) (string, error) {
	dataset := lsDataset[rule.LogSource.Category]
	if dataset == "" {
		dataset = "#event_simpleName=*"
	}

	condition, _ := detection["condition"].(string)
	clauses := map[string]string{}
	negated := map[string]bool{}

	// Detect negated selections in condition string.
	toks := lsCondRe.FindAllString(condition, -1)
	for i, tok := range toks {
		if strings.ToLower(tok) == "not" && i+1 < len(toks) {
			negated[toks[i+1]] = true
		}
	}

	for k, v := range detection {
		if k == "condition" {
			continue
		}
		sel, ok := toStringMapLS(v)
		if !ok {
			continue
		}
		clause, err := translateSelectionLS(sel)
		if err != nil {
			return "", err
		}
		clauses[k] = clause
	}

	whereExpr := buildConditionLS(condition, clauses, negated)

	// Project fields
	projectFields := lsProjectFields(rule.LogSource.Category)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("// %s\n", rule.Title))
	sb.WriteString(fmt.Sprintf("// Status: %s | Level: %s | ID: %s\n\n", rule.Status, rule.Level, rule.ID))
	sb.WriteString(dataset + "\n")
	if whereExpr != "" && whereExpr != "true" {
		sb.WriteString("| " + whereExpr + "\n")
	}
	sb.WriteString(fmt.Sprintf("| table([%s])\n", projectFields))
	sb.WriteString("| limit(1000)\n")
	return sb.String(), nil
}

func lsProjectFields(category string) string {
	switch category {
	case "network_connection":
		return "timestamp, ComputerName, RemoteAddressIP4, DomainName, ImageFileName"
	case "dns_query":
		return "timestamp, ComputerName, DomainName, RequestType"
	case "file_event":
		return "timestamp, ComputerName, FilePath, ImageFileName"
	case "process_creation", "process_access":
		return "timestamp, ComputerName, ImageFileName, CommandLine, ParentImageFileName"
	default:
		return "timestamp, ComputerName"
	}
}

func translateSelectionLS(sel map[string]interface{}) (string, error) {
	var parts []string
	for rawKey, rawVal := range sel {
		m := lsFieldRe.FindStringSubmatch(rawKey)
		if m == nil {
			continue
		}
		sigmaField, modifier := m[1], m[2]

		if strings.EqualFold(sigmaField, "Hashes") {
			parts = append(parts, buildHashExprLS(rawVal))
			continue
		}

		col := lsFieldMap[sigmaField]
		if col == "" {
			col = sigmaField
		}
		vals := toStringSliceLS(rawVal)
		if len(vals) == 0 {
			continue
		}
		parts = append(parts, buildFieldExprLS(col, modifier, vals))
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "true", nil
	}
	return strings.Join(parts, " AND "), nil
}

func buildFieldExprLS(col, modifier string, vals []string) string {
	switch strings.ToLower(modifier) {
	case "contains":
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s = *%s*`, col, v)
		}
		if len(preds) == 1 {
			return preds[0]
		}
		return "(" + strings.Join(preds, " OR ") + ")"
	case "startswith":
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s = %s*`, col, v)
		}
		if len(preds) == 1 {
			return preds[0]
		}
		return "(" + strings.Join(preds, " OR ") + ")"
	case "endswith":
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s = *%s`, col, v)
		}
		if len(preds) == 1 {
			return preds[0]
		}
		return "(" + strings.Join(preds, " OR ") + ")"
	default:
		if len(vals) == 1 {
			return fmt.Sprintf(`%s = "%s"`, col, vals[0])
		}
		quoted := make([]string, len(vals))
		for i, v := range vals {
			quoted[i] = `"` + v + `"`
		}
		return fmt.Sprintf(`%s IN [%s]`, col, strings.Join(quoted, ", "))
	}
}

func buildHashExprLS(rawVal interface{}) string {
	vals := toStringSliceLS(rawVal)
	var preds []string
	for _, v := range vals {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) != 2 {
			continue
		}
		algo := strings.ToLower(parts[0])
		hash := parts[1]
		var col string
		switch algo {
		case "md5":
			col = "MD5HashData"
		case "sha256":
			col = "SHA256HashData"
		case "sha1":
			col = "SHA1HashData"
		default:
			col = "SHA256HashData"
		}
		preds = append(preds, fmt.Sprintf(`%s = "%s"`, col, hash))
	}
	if len(preds) == 0 {
		return "true"
	}
	return "(" + strings.Join(preds, " OR ") + ")"
}

func buildConditionLS(condition string, clauses map[string]string, negated map[string]bool) string {
	if condition == "" {
		for _, v := range clauses {
			return v
		}
		return ""
	}
	toks := lsCondRe.FindAllString(condition, -1)
	var sb strings.Builder
	skipNext := false
	for i, tok := range toks {
		if skipNext {
			skipNext = false
			continue
		}
		switch strings.ToLower(tok) {
		case "or":
			sb.WriteString(" OR ")
		case "and":
			sb.WriteString(" AND ")
		case "not":
			// Next token is negated selection — emit NOT
			if i+1 < len(toks) {
				skipNext = true
				next := toks[i+1]
				if expr, ok := clauses[next]; ok {
					sb.WriteString("NOT (" + expr + ")")
				}
			}
		case "(", ")":
			sb.WriteString(tok)
		default:
			if expr, ok := clauses[tok]; ok {
				sb.WriteString(expr)
			} else {
				sb.WriteString(tok)
			}
		}
	}
	return sb.String()
}

var lsFieldRe = regexp.MustCompile(`^([^|]+)(?:\|(.+))?$`)
var lsCondRe = regexp.MustCompile(`[\w_\-]+|[()]`)

func toStringMapLS(v interface{}) (map[string]interface{}, bool) {
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

func toStringSliceLS(v interface{}) []string {
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
