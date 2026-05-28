package sigma

import (
	"fmt"
	"regexp"
)

var fieldModifierRe = regexp.MustCompile(`^([^|]+)(?:\|(.+))?$`)
var condTokenRe = regexp.MustCompile(`[\w_\-]+|[()]`)

// ParseField splits a raw Sigma detection key (e.g. "CommandLine|contains")
// into its field name and optional modifier. Always returns a non-empty field.
func ParseField(raw string) (field, modifier string) {
	m := fieldModifierRe.FindStringSubmatch(raw)
	if m == nil {
		return raw, ""
	}
	return m[1], m[2]
}

// TokenizeCondition splits a Sigma condition string into tokens (selection
// names, boolean operators, and parentheses).
func TokenizeCondition(cond string) []string {
	return condTokenRe.FindAllString(cond, -1)
}

// ToStringSlice normalises a yaml-decoded value (string, []interface{}, or
// numeric) to a []string.
func ToStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, item := range val {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	case int, int64, float64:
		return []string{fmt.Sprintf("%v", val)}
	}
	return nil
}

// ToStringMap coerces a yaml-decoded value to map[string]interface{}.
// Handles both map[string]interface{} (JSON-style) and map[interface{}]interface{}
// (YAML-style).
func ToStringMap(v interface{}) (map[string]interface{}, bool) {
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
