package chronicle

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

type Backend struct{}

func New() *Backend { return &Backend{} }

func (b *Backend) Name() string            { return "chronicle" }
func (b *Backend) OutputExtension() string { return ".yaral" }

func (b *Backend) Compile(sigmaYAML []byte) ([]byte, error) {
	rule, detection, err := parseSigma(sigmaYAML)
	if err != nil {
		return nil, fmt.Errorf("chronicle: %w", err)
	}
	yaral, err := buildYARAL(rule, detection)
	if err != nil {
		return nil, fmt.Errorf("chronicle: %w", err)
	}
	return []byte(yaral), nil
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

// Chronicle UDM event type per logsource category
var categoryEventType = map[string]string{
	"network_connection": "NETWORK_CONNECTION",
	"dns_query":          "NETWORK_DNS",
	"file_event":         "FILE_CREATION",
	"process_creation":   "PROCESS_LAUNCH",
	"process_access":     "PROCESS_OPEN",
	"registry_event":     "REGISTRY_CREATION",
}

// Sigma field → Chronicle UDM field (on event variable $e)
var fieldMap = map[string]string{
	"DestinationHostname": "$e.target.hostname",
	"DestinationIp":       "$e.target.ip",
	"Image":               "$e.principal.process.file.full_path",
	"ParentImage":         "$e.principal.process.parent_process.file.full_path",
	"CommandLine":         "$e.principal.process.command_line",
	"TargetFilename":      "$e.target.file.full_path",
	"TargetImage":         "$e.target.file.full_path",
	"SourceImage":         "$e.principal.process.file.full_path",
}

// Sigma level → Chronicle severity
var levelSeverity = map[string]string{
	"critical": "HIGH",
	"high":     "HIGH",
	"medium":   "MEDIUM",
	"low":      "LOW",
}

func buildYARAL(rule *sigmaRule, detection map[string]interface{}) (string, error) {
	eventType := categoryEventType[rule.LogSource.Category]
	if eventType == "" {
		eventType = "GENERIC_EVENT"
	}

	severity := levelSeverity[strings.ToLower(rule.Level)]
	if severity == "" {
		severity = "MEDIUM"
	}

	ruleName := toRuleName(rule.Title, rule.ID)

	condition, _ := detection["condition"].(string)
	clauses := map[string]string{}
	negated := map[string]bool{}
	for k, v := range detection {
		if k == "condition" {
			continue
		}
		sel, ok := toStringMap(v)
		if !ok {
			continue
		}
		clause, err := translateSelection(sel)
		if err != nil {
			return "", err
		}
		clauses[k] = clause
	}

	// Parse negation from condition (e.g. "selection and not filter")
	_ = negated
	eventExprs := buildConditionExprs(condition, clauses)

	// Extract MITRE technique IDs
	var mitreTags []string
	for _, tag := range rule.Tags {
		if strings.HasPrefix(strings.ToLower(tag), "attack.t") {
			tid := strings.ToUpper(strings.TrimPrefix(strings.ToLower(tag), "attack."))
			mitreTags = append(mitreTags, tid)
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("rule %s {\n", ruleName))
	sb.WriteString("  meta:\n")
	sb.WriteString(fmt.Sprintf("    author = \"dragnet-bot\"\n"))
	sb.WriteString(fmt.Sprintf("    description = %q\n", rule.Description))
	sb.WriteString(fmt.Sprintf("    severity = %q\n", severity))
	sb.WriteString(fmt.Sprintf("    rule_id = %q\n", rule.ID))
	sb.WriteString(fmt.Sprintf("    sigma_status = %q\n", rule.Status))
	if len(mitreTags) > 0 {
		sb.WriteString(fmt.Sprintf("    mitre_attack = %q\n", strings.Join(mitreTags, ", ")))
	}
	sb.WriteString("\n")
	sb.WriteString("  events:\n")
	sb.WriteString(fmt.Sprintf("    $e.metadata.event_type = \"%s\"\n", eventType))
	for _, expr := range eventExprs {
		sb.WriteString("    ")
		sb.WriteString(expr)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString("  condition:\n")
	sb.WriteString("    $e\n")
	sb.WriteString("}\n")
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

		udmField := fieldMap[sigmaField]
		if udmField == "" {
			udmField = "$e." + sigmaField
		}
		vals := toStringSlice(rawVal)
		if len(vals) == 0 {
			continue
		}
		parts = append(parts, buildFieldExpr(udmField, modifier, vals))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n    "), nil
}

func buildFieldExpr(udmField, modifier string, vals []string) string {
	switch strings.ToLower(modifier) {
	case "contains":
		if len(vals) == 1 {
			return fmt.Sprintf(`%s = /.*%s.*/i`, udmField, regexEscape(vals[0]))
		}
		patterns := make([]string, len(vals))
		for i, v := range vals {
			patterns[i] = regexEscape(v)
		}
		return fmt.Sprintf(`%s = /(%s)/i`, udmField, strings.Join(patterns, "|"))
	case "startswith":
		if len(vals) == 1 {
			return fmt.Sprintf(`%s = /^%s/i`, udmField, regexEscape(vals[0]))
		}
		patterns := make([]string, len(vals))
		for i, v := range vals {
			patterns[i] = "^" + regexEscape(v)
		}
		return fmt.Sprintf(`%s = /(%s)/i`, udmField, strings.Join(patterns, "|"))
	case "endswith":
		if len(vals) == 1 {
			return fmt.Sprintf(`%s = /%s$/i`, udmField, regexEscape(vals[0]))
		}
		patterns := make([]string, len(vals))
		for i, v := range vals {
			patterns[i] = regexEscape(v) + "$"
		}
		return fmt.Sprintf(`%s = /(%s)/i`, udmField, strings.Join(patterns, "|"))
	default:
		if len(vals) == 1 {
			return fmt.Sprintf(`%s = %q`, udmField, vals[0])
		}
		// YARA-L doesn't have IN; OR them
		preds := make([]string, len(vals))
		for i, v := range vals {
			preds[i] = fmt.Sprintf(`%s = %q`, udmField, v)
		}
		return "(" + strings.Join(preds, " or ") + ")"
	}
}

func buildHashExpr(rawVal interface{}) string {
	vals := toStringSlice(rawVal)
	var preds []string
	for _, v := range vals {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) != 2 {
			continue
		}
		algo := strings.ToLower(parts[0])
		hash := parts[1]
		var field string
		switch algo {
		case "sha256":
			field = "$e.target.file.sha256"
		case "sha1":
			field = "$e.target.file.sha1"
		case "md5":
			field = "$e.target.file.md5"
		default:
			field = "$e.target.file.sha256"
		}
		preds = append(preds, fmt.Sprintf(`%s = %q`, field, hash))
	}
	if len(preds) == 0 {
		return ""
	}
	return strings.Join(preds, "\n    ")
}

// buildConditionExprs resolves a Sigma condition string into a list of YARA-L event predicates.
func buildConditionExprs(condition string, clauses map[string]string) []string {
	if condition == "" {
		var out []string
		for _, v := range clauses {
			if v != "" {
				out = append(out, v)
			}
		}
		return out
	}

	// Simple approach: collect positive selections, skip negated ones.
	toks := condRe.FindAllString(condition, -1)
	var positive []string
	skip := false
	for i, tok := range toks {
		if strings.ToLower(tok) == "not" {
			skip = true
			continue
		}
		if strings.ToLower(tok) == "and" || strings.ToLower(tok) == "or" {
			skip = false
			continue
		}
		if tok == "(" || tok == ")" {
			continue
		}
		// If previous token was "not", this selection is a filter — skip it.
		if skip {
			skip = false
			continue
		}
		_ = i
		if expr, ok := clauses[tok]; ok && expr != "" {
			positive = append(positive, expr)
		}
	}
	return positive
}

// toRuleName converts a Sigma title+ID into a valid YARA-L rule name.
func toRuleName(title, id string) string {
	// Use last 8 chars of ID (no dashes) as suffix for uniqueness.
	suffix := strings.ReplaceAll(id, "-", "")
	if len(suffix) > 8 {
		suffix = suffix[len(suffix)-8:]
	}
	name := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return '_'
	}, title)
	// Collapse runs of underscores.
	for strings.Contains(name, "__") {
		name = strings.ReplaceAll(name, "__", "_")
	}
	name = strings.Trim(name, "_")
	if name == "" {
		name = "dragnet_rule"
	}
	return name + "_" + suffix
}

func regexEscape(s string) string {
	return regexp.QuoteMeta(s)
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
