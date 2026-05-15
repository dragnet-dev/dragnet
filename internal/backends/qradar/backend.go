package qradar

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Backend struct{}

func New() *Backend { return &Backend{} }

func (b *Backend) Name() string            { return "qradar" }
func (b *Backend) OutputExtension() string { return ".aql" }

func (b *Backend) Compile(sigmaYAML []byte) ([]byte, error) {
	rule, detection, err := parseSigma(sigmaYAML)
	if err != nil {
		return nil, fmt.Errorf("qradar: %w", err)
	}
	aql, err := buildAQL(rule, detection)
	if err != nil {
		return nil, fmt.Errorf("qradar: %w", err)
	}
	return []byte(aql), nil
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

// Sigma field → QRadar AQL field
var fieldMap = map[string]string{
	"DestinationHostname": "destinationhostname",
	"DestinationIp":       "destinationip",
	"Image":               "\"Application\"",
	"ParentImage":         "\"Application\"",
	"CommandLine":         "\"Command\"",
	"TargetFilename":      "filename",
	"TargetImage":         "filename",
	"SourceImage":         "\"Application\"",
}

var categorySelect = map[string]string{
	"network_connection": "DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS \"Start Time\", sourceip, destinationip, destinationhostname, destinationport",
	"dns_query":          "DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS \"Start Time\", sourceip, destinationhostname",
	"file_event":         "DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS \"Start Time\", sourceip, filename, \"Application\"",
	"process_creation":   "DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS \"Start Time\", sourceip, \"Application\", \"Command\"",
	"process_access":     "DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS \"Start Time\", sourceip, \"Application\"",
}

func buildAQL(rule *sigmaRule, detection map[string]interface{}) (string, error) {
	sel := categorySelect[rule.LogSource.Category]
	if sel == "" {
		sel = "DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') AS \"Start Time\", sourceip, destinationip"
	}

	condition, _ := detection["condition"].(string)
	clauses := map[string]string{}
	for k, v := range detection {
		if k == "condition" {
			continue
		}
		selMap, ok := toStringMap(v)
		if !ok {
			continue
		}
		clause, err := translateSelection(selMap)
		if err != nil {
			return "", err
		}
		clauses[k] = clause
	}

	where := buildCondition(condition, clauses)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("-- %s\n", rule.Title))
	sb.WriteString(fmt.Sprintf("-- Status: %s | Level: %s | ID: %s\n", rule.Status, rule.Level, rule.ID))
	sb.WriteString(fmt.Sprintf("SELECT %s\n", sel))
	sb.WriteString("FROM events\n")
	if where != "" && where != "true" {
		sb.WriteString(fmt.Sprintf("WHERE %s\n", where))
	}
	sb.WriteString("LAST 24 HOURS\n")
	return sb.String(), nil
}

func translateSelection(sel map[string]interface{}) (string, error) {
	var parts []string
	for rawKey, rawVal := range sel {
		m := fieldRe.FindStringSubmatch(rawKey)
		if m == nil {
			continue
		}
		sigmaField, modifier := m[1], m[2]

		if strings.EqualFold(sigmaField, "Hashes") {
			parts = append(parts, buildHashExpr(rawVal))
			continue
		}

		col := fieldMap[sigmaField]
		if col == "" {
			col = sigmaField
		}
		vals := toStringSlice(rawVal)
		if len(vals) == 0 {
			continue
		}
		parts = append(parts, buildFieldExpr(col, modifier, vals))
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "true", nil
	}
	return strings.Join(parts, "\n  AND "), nil
}

func buildFieldExpr(col, modifier string, vals []string) string {
	switch strings.ToLower(modifier) {
	case "contains":
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s ILIKE '%%%s%%'`, col, v)
		}
		return "(" + strings.Join(preds, " OR ") + ")"
	case "startswith":
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s ILIKE '%s%%'`, col, v)
		}
		return "(" + strings.Join(preds, " OR ") + ")"
	case "endswith":
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s ILIKE '%%%s'`, col, v)
		}
		return "(" + strings.Join(preds, " OR ") + ")"
	default:
		if len(vals) == 1 {
			return fmt.Sprintf(`%s = '%s'`, col, vals[0])
		}
		quoted := make([]string, len(vals))
		for i, v := range vals {
			quoted[i] = "'" + v + "'"
		}
		return fmt.Sprintf(`%s IN (%s)`, col, strings.Join(quoted, ", "))
	}
}

func buildHashExpr(rawVal interface{}) string {
	vals := toStringSlice(rawVal)
	var preds []string
	for _, v := range vals {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) == 2 {
			algo := strings.ToLower(parts[0])
			hash := parts[1]
			var col string
			switch algo {
			case "sha256":
				col = "sha256hash"
			case "sha1":
				col = "sha1hash"
			case "md5":
				col = "md5hash"
			default:
				col = "sha256hash"
			}
			preds = append(preds, fmt.Sprintf(`%s = '%s'`, col, hash))
		}
	}
	if len(preds) == 0 {
		return "true"
	}
	return "(" + strings.Join(preds, " OR ") + ")"
}

func buildCondition(condition string, clauses map[string]string) string {
	if condition == "" {
		for _, v := range clauses {
			return v
		}
		return ""
	}
	toks := condRe.FindAllString(condition, -1)
	var sb strings.Builder
	for _, tok := range toks {
		switch strings.ToLower(tok) {
		case "or":
			sb.WriteString(" OR ")
		case "and":
			sb.WriteString(" AND ")
		case "not":
			sb.WriteString(" NOT ")
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

var fieldRe = regexp.MustCompile(`^([^|]+)(?:\|(.+))?$`)
var condRe = regexp.MustCompile(`[\w_\-]+|[()]`)

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
