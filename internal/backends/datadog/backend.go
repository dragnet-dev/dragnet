package datadog

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Backend struct{}

func New() *Backend { return &Backend{} }

func (b *Backend) Name() string            { return "datadog" }
func (b *Backend) OutputExtension() string { return ".json" }

func (b *Backend) Compile(sigmaYAML []byte) ([]byte, error) {
	rule, detection, err := parseSigma(sigmaYAML)
	if err != nil {
		return nil, fmt.Errorf("datadog: %w", err)
	}
	out, err := buildDatadogRule(rule, detection)
	if err != nil {
		return nil, fmt.Errorf("datadog: %w", err)
	}
	return out, nil
}

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

// Sigma field → Datadog log attribute (using @attribute syntax)
var fieldMap = map[string]string{
	"DestinationHostname": "@network.destination.hostname",
	"DestinationIp":       "@network.destination.ip",
	"Image":               "@process.name",
	"ParentImage":         "@process.parent.name",
	"CommandLine":         "@process.command_line",
	"TargetFilename":      "@file.path",
	"TargetImage":         "@file.path",
	"SourceImage":         "@process.name",
}

var levelStatus = map[string]string{
	"critical": "critical",
	"high":     "high",
	"medium":   "medium",
	"low":      "low",
}

// Datadog rule JSON structure
type ddRule struct {
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Queries   []ddQuery `json:"queries"`
	Cases     []ddCase  `json:"cases"`
	Options   ddOptions `json:"options"`
	Message   string    `json:"message"`
	Tags      []string  `json:"tags"`
	IsEnabled bool      `json:"isEnabled"`
}

type ddQuery struct {
	Name          string   `json:"name"`
	Query         string   `json:"query"`
	Aggregation   string   `json:"aggregation"`
	GroupByFields []string `json:"groupByFields"`
}

type ddCase struct {
	Name          string   `json:"name"`
	Status        string   `json:"status"`
	Condition     string   `json:"condition"`
	Notifications []string `json:"notifications"`
}

type ddOptions struct {
	EvaluationWindow  int    `json:"evaluationWindow"`
	KeepAlive         int    `json:"keepAlive"`
	MaxSignalDuration int    `json:"maxSignalDuration"`
	DetectionMethod   string `json:"detectionMethod"`
}

func buildDatadogRule(rule *sigmaRule, detection map[string]interface{}) ([]byte, error) {
	status := levelStatus[strings.ToLower(rule.Level)]
	if status == "" {
		status = "medium"
	}

	condition, _ := detection["condition"].(string)
	clauses := map[string]string{}
	negatedClauses := map[string]string{}
	for k, v := range detection {
		if k == "condition" {
			continue
		}
		sel, ok := toStringMap(v)
		if !ok {
			continue
		}
		q, err := translateSelection(sel)
		if err != nil {
			return nil, err
		}
		clauses[k] = q
	}

	query := buildQuery(condition, clauses, negatedClauses)

	// Build Datadog tags from Sigma tags and metadata.
	ddTags := []string{"source:dragnet", "security:supply-chain"}
	for _, tag := range rule.Tags {
		if strings.HasPrefix(strings.ToLower(tag), "attack.t") {
			tid := strings.ToLower(strings.TrimPrefix(strings.ToLower(tag), "attack."))
			ddTags = append(ddTags, "mitre:"+tid)
		}
	}

	dr := ddRule{
		Name: rule.Title,
		Type: "log_detection",
		Queries: []ddQuery{
			{
				Name:          "a",
				Query:         query,
				Aggregation:   "count",
				GroupByFields: []string{},
			},
		},
		Cases: []ddCase{
			{
				Name:          "Detected",
				Status:        status,
				Condition:     "a > 0",
				Notifications: []string{},
			},
		},
		Options: ddOptions{
			EvaluationWindow:  300,
			KeepAlive:         3600,
			MaxSignalDuration: 86400,
			DetectionMethod:   "threshold",
		},
		Message:   fmt.Sprintf("%s\n\nSigma ID: %s | Status: %s", rule.Description, rule.ID, rule.Status),
		Tags:      ddTags,
		IsEnabled: true,
	}

	return json.MarshalIndent(dr, "", "  ")
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
			parts = append(parts, buildHashQuery(rawVal))
			continue
		}

		col := fieldMap[sigmaField]
		if col == "" {
			col = "@" + sigmaField
		}
		vals := toStringSlice(rawVal)
		if len(vals) == 0 {
			continue
		}
		parts = append(parts, buildFieldQuery(col, modifier, vals))
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "*", nil
	}
	return strings.Join(parts, " "), nil
}

func buildFieldQuery(col, modifier string, vals []string) string {
	switch strings.ToLower(modifier) {
	case "contains":
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s:*%s*`, col, v)
		}
		if len(preds) == 1 {
			return preds[0]
		}
		return "(" + strings.Join(preds, " OR ") + ")"
	case "startswith":
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s:%s*`, col, v)
		}
		if len(preds) == 1 {
			return preds[0]
		}
		return "(" + strings.Join(preds, " OR ") + ")"
	case "endswith":
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s:*%s`, col, v)
		}
		if len(preds) == 1 {
			return preds[0]
		}
		return "(" + strings.Join(preds, " OR ") + ")"
	default:
		if len(vals) == 1 {
			return fmt.Sprintf(`%s:%s`, col, vals[0])
		}
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s:%s`, col, v)
		}
		return "(" + strings.Join(preds, " OR ") + ")"
	}
}

func buildHashQuery(rawVal interface{}) string {
	vals := toStringSlice(rawVal)
	var preds []string
	for _, v := range vals {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) == 2 {
			algo := strings.ToLower(parts[0])
			hash := parts[1]
			preds = append(preds, fmt.Sprintf(`@file.hash.%s:%s`, algo, hash))
		}
	}
	if len(preds) == 0 {
		return "*"
	}
	return "(" + strings.Join(preds, " OR ") + ")"
}

func buildQuery(condition string, clauses, negated map[string]string) string {
	if condition == "" {
		var parts []string
		for _, v := range clauses {
			if v != "" && v != "*" {
				parts = append(parts, v)
			}
		}
		if len(parts) == 0 {
			return "*"
		}
		return strings.Join(parts, " ")
	}

	toks := condRe.FindAllString(condition, -1)
	var sb strings.Builder
	notNext := false
	for _, tok := range toks {
		switch strings.ToLower(tok) {
		case "or":
			sb.WriteString(" OR ")
		case "and":
			sb.WriteString(" ")
		case "not":
			notNext = true
		case "(":
			sb.WriteString("(")
		case ")":
			sb.WriteString(")")
		default:
			expr := tok
			if e, ok := clauses[tok]; ok {
				expr = e
			}
			if notNext {
				sb.WriteString("-")
				notNext = false
			}
			sb.WriteString(expr)
		}
	}
	q := sb.String()
	if q == "" {
		return "*"
	}
	return q
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
