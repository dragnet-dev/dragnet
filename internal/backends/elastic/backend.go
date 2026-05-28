package elastic

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dragnet-dev/dragnet/internal/backends/sigma"
)

type Backend struct{}

func New() *Backend { return &Backend{} }

func (b *Backend) Name() string            { return "elastic" }
func (b *Backend) OutputExtension() string { return ".eql" }

func (b *Backend) Compile(sigmaYAML []byte) ([]byte, error) {
	rule, detection, err := parseSigma(sigmaYAML)
	if err != nil {
		return nil, fmt.Errorf("elastic: %w", err)
	}
	eql, err := buildEQL(rule, detection)
	if err != nil {
		return nil, fmt.Errorf("elastic: %w", err)
	}
	return []byte(eql), nil
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

// EQL event category mapping
var categoryEvent = map[string]string{
	"network_connection": "network",
	"dns_query":          "network",
	"file_event":         "file",
	"process_creation":   "process",
	"process_access":     "process",
	"registry_event":     "registry",
}

// Sigma field → ECS field
var fieldMap = map[string]string{
	"DestinationHostname": "destination.domain",
	"DestinationIp":       "destination.ip",
	"Image":               "process.executable",
	"ParentImage":         "process.parent.executable",
	"CommandLine":         "process.command_line",
	"TargetFilename":      "file.path",
	"TargetImage":         "file.path",
	"SourceImage":         "process.executable",
}

func buildEQL(rule *sigmaRule, detection map[string]interface{}) (string, error) {
	eventType := categoryEvent[rule.LogSource.Category]
	if eventType == "" {
		eventType = "any"
	}

	condition, _ := detection["condition"].(string)
	clauses := map[string]string{}
	for k, v := range detection {
		if k == "condition" {
			continue
		}
		sel, ok := sigma.ToStringMap(v)
		if !ok {
			continue
		}
		clause, err := translateSelection(sel)
		if err != nil {
			return "", err
		}
		clauses[k] = clause
	}

	where := buildCondition(condition, clauses)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("// %s\n", rule.Title))
	sb.WriteString(fmt.Sprintf("// Status: %s | Level: %s | ID: %s\n\n", rule.Status, rule.Level, rule.ID))
	sb.WriteString(eventType)
	if where != "" && where != "true" {
		sb.WriteString(" where\n  ")
		sb.WriteString(where)
	}
	sb.WriteString("\n")
	return sb.String(), nil
}

func translateSelection(sel map[string]interface{}) (string, error) {
	var parts []string
	for rawKey, rawVal := range sel {
		sigmaField, modifier := sigma.ParseField(rawKey)

		if strings.EqualFold(sigmaField, "Hashes") {
			parts = append(parts, buildHashExpr(rawVal))
			continue
		}

		col := fieldMap[sigmaField]
		if col == "" {
			col = sigmaField
		}
		vals := sigma.ToStringSlice(rawVal)
		if len(vals) == 0 {
			continue
		}
		parts = append(parts, buildFieldExpr(col, modifier, vals))
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "true", nil
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	joined := make([]string, len(parts))
	for i, p := range parts {
		joined[i] = "(" + p + ")"
	}
	return strings.Join(joined, " and\n  "), nil
}

func buildFieldExpr(col, modifier string, vals []string) string {
	switch strings.ToLower(modifier) {
	case "contains":
		if len(vals) == 1 {
			return fmt.Sprintf(`%s like~ "*%s*"`, col, vals[0])
		}
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s like~ "*%s*"`, col, v)
		}
		return "(" + strings.Join(preds, " or ") + ")"
	case "startswith":
		if len(vals) == 1 {
			return fmt.Sprintf(`%s like~ "%s*"`, col, vals[0])
		}
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s like~ "%s*"`, col, v)
		}
		return "(" + strings.Join(preds, " or ") + ")"
	case "endswith":
		if len(vals) == 1 {
			return fmt.Sprintf(`%s like~ "*%s"`, col, vals[0])
		}
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s like~ "*%s"`, col, v)
		}
		return "(" + strings.Join(preds, " or ") + ")"
	default:
		if len(vals) == 1 {
			return fmt.Sprintf(`%s == "%s"`, col, vals[0])
		}
		quoted := make([]string, len(vals))
		for i, v := range vals {
			quoted[i] = `"` + v + `"`
		}
		return fmt.Sprintf(`%s in~ (%s)`, col, strings.Join(quoted, ", "))
	}
}

func buildHashExpr(rawVal interface{}) string {
	vals := sigma.ToStringSlice(rawVal)
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
		case "sha256":
			col = "process.hash.sha256"
		case "sha1":
			col = "process.hash.sha1"
		case "md5":
			col = "process.hash.md5"
		default:
			col = "process.hash.sha256"
		}
		preds = append(preds, fmt.Sprintf(`%s == "%s"`, col, hash))
	}
	if len(preds) == 0 {
		return "true"
	}
	return "(" + strings.Join(preds, " or ") + ")"
}

func buildCondition(condition string, clauses map[string]string) string {
	if condition == "" {
		for _, v := range clauses {
			return v
		}
		return ""
	}
	toks := sigma.TokenizeCondition(condition)
	var sb strings.Builder
	for _, tok := range toks {
		switch strings.ToLower(tok) {
		case "or":
			sb.WriteString(" or ")
		case "and":
			sb.WriteString(" and ")
		case "not":
			sb.WriteString("not ")
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

