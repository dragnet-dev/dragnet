package incident

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	dragschema "github.com/dragnet-dev/dragnet/schema"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

// Load reads a YAML incident file, validates it against the JSON schema, and
// returns the parsed Incident. Schema path defaults to schema/incident.schema.json
// relative to the working directory.
func Load(path string) (*Incident, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse yaml %s: %w", path, err)
	}
	raw = normaliseYAML(raw)

	if err := validateSchema(raw); err != nil {
		return nil, fmt.Errorf("schema %s: %w", path, err)
	}

	var inc Incident
	if err := yaml.Unmarshal(data, &inc); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return &inc, nil
}

// LoadDraft reads a YAML draft incident file and returns the parsed Incident
// without running JSON schema validation. Drafts are work-in-progress and may
// not satisfy the full schema (e.g. missing packages, unknown attack_type).
func LoadDraft(path string) (*Incident, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var inc Incident
	if err := yaml.Unmarshal(data, &inc); err != nil {
		return nil, fmt.Errorf("parse yaml %s: %w", path, err)
	}
	return &inc, nil
}

const incidentSchemaID = "https://dragnet.dev/schemas/incident.schema.json"

func validateSchema(doc any) error {
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(incidentSchemaID, bytes.NewReader(dragschema.IncidentJSON)); err != nil {
		return fmt.Errorf("add schema resource: %w", err)
	}
	sch, err := compiler.Compile(incidentSchemaID)
	if err != nil {
		return fmt.Errorf("compile schema: %w", err)
	}

	jsonBytes, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal for schema: %w", err)
	}
	var jsonDoc any
	if err := json.Unmarshal(jsonBytes, &jsonDoc); err != nil {
		return err
	}
	return sch.Validate(jsonDoc)
}

// normaliseYAML converts map[interface{}]interface{} (produced by go-yaml v2
// style) to map[string]interface{} so json.Marshal works correctly.
func normaliseYAML(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			out[k] = normaliseYAML(val)
		}
		return out
	case []any:
		for i, item := range v {
			v[i] = normaliseYAML(item)
		}
		return v
	default:
		return v
	}
}
