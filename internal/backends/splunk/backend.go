package splunk

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dragnet-dev/dragnet/internal/backends/sigma"
)

type Backend struct{}

func New() *Backend { return &Backend{} }

func (b *Backend) Name() string            { return "splunk" }
func (b *Backend) OutputExtension() string { return ".spl" }

func (b *Backend) Compile(sigmaYAML []byte) ([]byte, error) {
	rule, detection, err := parseSigma(sigmaYAML)
	if err != nil {
		return nil, fmt.Errorf("splunk: %w", err)
	}
	spl, err := buildSPL(rule, detection)
	if err != nil {
		return nil, fmt.Errorf("splunk: %w", err)
	}
	return []byte(spl), nil
}

// ---- Sigma parser ----

type sigmaRule struct {
	Title       string    `yaml:"title"`
	ID          string    `yaml:"id"`
	Status      string    `yaml:"status"`
	Level       string    `yaml:"level"`
	LogSource   logSource `yaml:"logsource"`
	References  []string  `yaml:"references"`
	Description string    `yaml:"description"`
}

type logSource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
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

// ---- field mapping ----

var fieldMap = map[string]string{
	"DestinationHostname": "dest",
	"DestinationIp":       "dest_ip",
	"Image":               "process",
	"ParentImage":         "parent_process",
	"CommandLine":         "CommandLine",
	"TargetFilename":      "file_path",
	"TargetImage":         "process",
	"SourceImage":         "parent_process",
}

var categoryTable = map[string]string{
	"network_connection": "* sourcetype=network*",
	"dns_query":          "* sourcetype=network*",
	"file_event":         "* sourcetype=file*",
	"process_creation":   "* sourcetype=endpoint*",
	"process_access":     "* sourcetype=endpoint*",
	"registry_event":     "* sourcetype=endpoint*",
}

var categoryFields = map[string]string{
	"network_connection": "_time, src, dest, dest_ip, process",
	"dns_query":          "_time, src, query, record_type",
	"file_event":         "_time, host, file_path, file_hash",
	"process_creation":   "_time, host, process, parent_process, CommandLine",
	"process_access":     "_time, host, process, parent_process",
}

// ---- SPL builder ----

func buildSPL(rule *sigmaRule, detection map[string]interface{}) (string, error) {
	source := categoryTable[rule.LogSource.Category]
	if source == "" {
		source = "*"
	}
	fields := categoryFields[rule.LogSource.Category]
	if fields == "" {
		fields = "_time, host"
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
	sb.WriteString(fmt.Sprintf("| comment \"%s\"\n", rule.Title))
	sb.WriteString(fmt.Sprintf("| comment \"Status: %s | Level: %s | ID: %s\"\n", rule.Status, rule.Level, rule.ID))
	sb.WriteString(fmt.Sprintf("index=%s\n", source))
	if where != "" && where != "true" {
		sb.WriteString(fmt.Sprintf("| where %s\n", where))
	}
	sb.WriteString(fmt.Sprintf("| table %s\n", fields))
	sb.WriteString("| head 1000\n")
	return sb.String(), nil
}

func translateSelection(sel map[string]interface{}) (string, error) {
	var parts []string
	for rawKey, rawVal := range sel {
		sigmaField, modifier := sigma.ParseField(rawKey)

		if strings.EqualFold(sigmaField, "Hashes") {
			expr := buildHashExpr(rawVal)
			parts = append(parts, expr)
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
	return strings.Join(parts, " AND "), nil
}

func buildFieldExpr(col, modifier string, vals []string) string {
	switch strings.ToLower(modifier) {
	case "contains":
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s="*%s*"`, col, v)
		}
		return "(" + strings.Join(preds, " OR ") + ")"
	case "startswith":
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s="%s*"`, col, v)
		}
		return "(" + strings.Join(preds, " OR ") + ")"
	case "endswith":
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s="*%s"`, col, v)
		}
		return "(" + strings.Join(preds, " OR ") + ")"
	default:
		if len(vals) == 1 {
			return fmt.Sprintf(`%s="%s"`, col, vals[0])
		}
		quoted := make([]string, len(vals))
		for i, v := range vals {
			quoted[i] = `"` + v + `"`
		}
		return fmt.Sprintf(`%s IN (%s)`, col, strings.Join(quoted, ", "))
	}
}

func buildHashExpr(rawVal interface{}) string {
	vals := sigma.ToStringSlice(rawVal)
	var preds []string
	for _, v := range vals {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) == 2 {
			algo := strings.ToLower(parts[0])
			hash := parts[1]
			preds = append(preds, fmt.Sprintf(`file_hash_%s="%s"`, algo, hash))
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
	toks := sigma.TokenizeCondition(condition)
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

