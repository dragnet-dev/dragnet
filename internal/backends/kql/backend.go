package kql

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dragnet-dev/dragnet/internal/backends/sigma"
)

// Backend compiles Sigma rules to KQL for Microsoft Sentinel / MDE.
type Backend struct{}

func New() *Backend { return &Backend{} }

func (b *Backend) Name() string            { return "kql" }
func (b *Backend) OutputExtension() string { return ".kql" }

func (b *Backend) Compile(sigmaYAML []byte) ([]byte, error) {
	rule, rawDetection, err := parseSigma(sigmaYAML)
	if err != nil {
		return nil, fmt.Errorf("kql: parse sigma: %w", err)
	}

	kql, err := buildKQL(rule, rawDetection)
	if err != nil {
		return nil, fmt.Errorf("kql: build kql: %w", err)
	}
	return []byte(kql), nil
}

// ---- Sigma structs ----

type sigmaRule struct {
	Title       string    `yaml:"title"`
	ID          string    `yaml:"id"`
	Status      string    `yaml:"status"`
	Description string    `yaml:"description"`
	LogSource   logSource `yaml:"logsource"`
	Level       string    `yaml:"level"`
	Tags        []string  `yaml:"tags"`
	References  []string  `yaml:"references"`
}

type logSource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
}

// parseSigma unmarshals the Sigma YAML and returns the rule metadata plus the
// raw detection map (keyed by selection name or "condition").
func parseSigma(data []byte) (*sigmaRule, map[string]interface{}, error) {
	var rule sigmaRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, nil, err
	}

	// Unmarshal the whole doc as a generic map to get the detection block.
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}

	rawDet, ok := doc["detection"]
	if !ok {
		return &rule, map[string]interface{}{}, nil
	}

	detMap, ok := rawDet.(map[string]interface{})
	if !ok {
		return &rule, map[string]interface{}{}, nil
	}

	return &rule, detMap, nil
}

// ---- KQL builder ----

func buildKQL(rule *sigmaRule, rawDetection map[string]interface{}) (string, error) {
	table := tableMap[rule.LogSource.Category]
	if table == "" {
		table = "DeviceEvents"
	}

	condition, _ := rawDetection["condition"].(string)

	// Build per-selection KQL clauses.
	selectionClauses := map[string]string{}
	for key, val := range rawDetection {
		if key == "condition" {
			continue
		}
		selMap, ok := sigma.ToStringMap(val)
		if !ok {
			continue
		}
		clause, err := translateSelection(selMap)
		if err != nil {
			return "", fmt.Errorf("selection %q: %w", key, err)
		}
		selectionClauses[key] = clause
	}

	whereClause := buildCondition(condition, selectionClauses)

	// Project fields.
	fields := projectFields[table]
	if len(fields) == 0 {
		fields = []string{"Timestamp", "DeviceName"}
	}

	var sb strings.Builder

	// Header comments.
	sb.WriteString(fmt.Sprintf("// %s\n", rule.Title))
	sb.WriteString(fmt.Sprintf("// Status: %s | Level: %s\n", rule.Status, rule.Level))
	if rule.ID != "" {
		sb.WriteString(fmt.Sprintf("// ID: %s\n", rule.ID))
	}
	sb.WriteString("\n")

	sb.WriteString(table + "\n")
	sb.WriteString("| where " + whereClause + "\n")
	sb.WriteString("| project " + strings.Join(fields, ", ") + "\n")
	sb.WriteString("| limit 1000\n")

	return sb.String(), nil
}

// translateSelection converts a Sigma selection block into a KQL boolean expression.
// Multiple field entries within a selection are ANDed together.
func translateSelection(sel map[string]interface{}) (string, error) {
	parts := make([]string, 0, len(sel))

	for rawKey, rawVal := range sel {
		sigmaField, modifier := sigma.ParseField(rawKey)

		kqlCol := fieldMap[sigmaField]
		if kqlCol == "" {
			kqlCol = sigmaField // pass through unknown fields unchanged
		}

		expr, err := buildFieldExpr(kqlCol, sigmaField, modifier, rawVal)
		if err != nil {
			return "", err
		}
		parts = append(parts, expr)
	}

	if len(parts) == 0 {
		return "true", nil
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	sort.Strings(parts) // deterministic output regardless of map iteration order
	joined := make([]string, len(parts))
	for i, p := range parts {
		joined[i] = "(" + p + ")"
	}
	return strings.Join(joined, "\n    and "), nil
}

// buildFieldExpr builds a single KQL predicate for one field+modifier+value combo.
func buildFieldExpr(kqlCol, sigmaField, modifier string, rawVal interface{}) (string, error) {
	// Special handling for Hashes field.
	if sigmaField == "Hashes" {
		return buildHashExpr(rawVal)
	}

	values := sigma.ToStringSlice(rawVal)
	if len(values) == 0 {
		return "true", nil
	}

	op := modifierToOp(modifier)

	if len(values) == 1 {
		return fmt.Sprintf(`%s %s "%s"`, kqlCol, op, values[0]), nil
	}

	// Multi-value: use has_any / in~ / etc.
	switch op {
	case "has":
		quoted := quoteList(values)
		return fmt.Sprintf(`%s has_any (%s)`, kqlCol, quoted), nil
	case "startswith":
		// KQL doesn't have startswith_any; OR them.
		preds := make([]string, len(values))
		for i, v := range values {
			preds[i] = fmt.Sprintf(`%s startswith "%s"`, kqlCol, v)
		}
		return "(" + strings.Join(preds, " or ") + ")", nil
	case "endswith":
		preds := make([]string, len(values))
		for i, v := range values {
			preds[i] = fmt.Sprintf(`%s endswith "%s"`, kqlCol, v)
		}
		return "(" + strings.Join(preds, " or ") + ")", nil
	default:
		// == comparison uses in~
		quoted := quoteList(values)
		return fmt.Sprintf(`%s in~ (%s)`, kqlCol, quoted), nil
	}
}

// buildHashExpr handles the Sigma Hashes field (e.g. "SHA256=abc123...").
func buildHashExpr(rawVal interface{}) (string, error) {
	values := sigma.ToStringSlice(rawVal)
	if len(values) == 0 {
		return "true", nil
	}

	// Group by algorithm.
	byAlgo := map[string][]string{}
	for _, v := range values {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) == 2 {
			algo := strings.ToUpper(parts[0])
			hash := parts[1]
			byAlgo[algo] = append(byAlgo[algo], hash)
		} else {
			// Unknown format — treat as SHA256 by default.
			byAlgo["SHA256"] = append(byAlgo["SHA256"], v)
		}
	}

	preds := make([]string, 0, len(byAlgo))
	for algo, hashes := range byAlgo {
		col := algoToColumn(algo)
		if len(hashes) == 1 {
			preds = append(preds, fmt.Sprintf(`%s == "%s"`, col, hashes[0]))
		} else {
			preds = append(preds, fmt.Sprintf(`%s in~ (%s)`, col, quoteList(hashes)))
		}
	}

	if len(preds) == 1 {
		return preds[0], nil
	}
	return "(" + strings.Join(preds, " or ") + ")", nil
}

func algoToColumn(algo string) string {
	switch algo {
	case "MD5":
		return "MD5"
	case "SHA1":
		return "SHA1"
	default:
		return "SHA256"
	}
}

// modifierToOp maps a Sigma modifier string to a KQL operator token.
func modifierToOp(modifier string) string {
	switch strings.ToLower(modifier) {
	case "contains":
		return "has"
	case "startswith":
		return "startswith"
	case "endswith":
		return "endswith"
	default:
		return "==" // exact match / no modifier
	}
}

// buildCondition assembles the top-level where clause from the condition string
// and the map of per-selection KQL expressions.
func buildCondition(condition string, clauses map[string]string) string {
	if condition == "" {
		// Single unnamed selection.
		for _, v := range clauses {
			return v
		}
		return "true"
	}

	// Tokenise the condition: words (selection names), "or", "and", "not", parens.
	tokens := sigma.TokenizeCondition(condition)
	var sb strings.Builder
	for i, tok := range tokens {
		switch strings.ToLower(tok) {
		case "or":
			sb.WriteString("\n    or ")
		case "and":
			sb.WriteString("\n    and ")
		case "not":
			if i > 0 {
				sb.WriteString(" ")
			}
			sb.WriteString("not ")
		case "(":
			sb.WriteString("(")
		case ")":
			sb.WriteString(")")
		default:
			expr := tok
			if e, ok := clauses[tok]; ok {
				expr = e
			}
			if i > 0 && !strings.HasSuffix(sb.String(), " ") && !strings.HasSuffix(sb.String(), "(") {
				sb.WriteString(" ")
			}
			sb.WriteString(expr)
		}
	}
	return sb.String()
}

// quoteList returns comma-separated double-quoted values suitable for KQL list literals.
func quoteList(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = fmt.Sprintf(`"%s"`, v)
	}
	return strings.Join(quoted, ", ")
}
