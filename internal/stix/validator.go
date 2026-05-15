package stix

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	dragschema "github.com/dragnet-dev/dragnet/schema"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

// bundleSchemaID is the $id of the bundle schema — used as the compiler entry point.
const bundleSchemaID = "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/common/bundle.json"

// uuidRE matches the UUID4 portion of a STIX ID (lowercase hex, hyphens in correct positions).
var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidationError describes a single structural problem in a STIX bundle.
type ValidationError struct {
	ObjectID string
	Field    string
	Message  string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("object %s field %s: %s", e.ObjectID, e.Field, e.Message)
}

// Validate checks a Bundle in two passes:
//  1. Structural — required fields, ID format, relationship ref resolution. Always runs.
//  2. Official STIX 2.1 JSON schema — validates enums, patterns, and type-specific rules.
//     Runs only when schema/stix/ is present; skips gracefully otherwise.
//
// Returns all errors found across both passes.
func Validate(b Bundle) []ValidationError {
	errs := structuralValidate(b)

	if schemaErrs := officialSchemaValidate(b); len(schemaErrs) > 0 {
		errs = append(errs, schemaErrs...)
	}

	return errs
}

// structuralValidate checks required fields and ref resolution without any schema file.
func structuralValidate(b Bundle) []ValidationError {
	var errs []ValidationError

	add := func(id, field, msg string) {
		errs = append(errs, ValidationError{ObjectID: id, Field: field, Message: msg})
	}

	if b.Type != "bundle" {
		add(b.ID, "type", fmt.Sprintf("expected 'bundle', got %q", b.Type))
	}
	if b.ID == "" {
		add("(bundle)", "id", "bundle ID is empty")
	}

	// Build ID set for relationship ref resolution
	ids := make(map[string]bool, len(b.Objects))
	for _, obj := range b.Objects {
		if id := objectID(obj); id != "" {
			ids[id] = true
		}
	}

	for _, obj := range b.Objects {
		switch v := obj.(type) {
		case Identity:
			checkCommon(v.Common, add)
			if v.Name == "" {
				add(v.ID, "name", "required")
			}
			if v.IdentityClass == "" {
				add(v.ID, "identity_class", "required")
			}
		case Indicator:
			checkCommon(v.Common, add)
			if v.Pattern == "" {
				add(v.ID, "pattern", "required")
			}
			if v.PatternType != "stix" {
				add(v.ID, "pattern_type", fmt.Sprintf("expected 'stix', got %q", v.PatternType))
			}
			if v.ValidFrom.IsZero() {
				add(v.ID, "valid_from", "required and must be non-zero")
			}
			if len(v.IndicatorTypes) == 0 {
				add(v.ID, "indicator_types", "required and must be non-empty")
			}
		case Malware:
			checkCommon(v.Common, add)
			if len(v.MalwareTypes) == 0 {
				add(v.ID, "malware_types", "required and must be non-empty")
			}
		case ThreatActor:
			checkCommon(v.Common, add)
			if len(v.ThreatActorTypes) == 0 {
				add(v.ID, "threat_actor_types", "required and must be non-empty")
			}
		case Campaign:
			checkCommon(v.Common, add)
			if v.Name == "" {
				add(v.ID, "name", "required")
			}
		case AttackPattern:
			checkCommon(v.Common, add)
			if v.Name == "" {
				add(v.ID, "name", "required")
			}
		case Vulnerability:
			checkCommon(v.Common, add)
			if v.Name == "" {
				add(v.ID, "name", "required")
			}
		case Relationship:
			checkCommon(v.Common, add)
			if v.RelationshipType == "" {
				add(v.ID, "relationship_type", "required")
			}
			if v.SourceRef == "" {
				add(v.ID, "source_ref", "required")
			} else if !ids[v.SourceRef] {
				add(v.ID, "source_ref", fmt.Sprintf("%q does not resolve to any object in this bundle", v.SourceRef))
			}
			if v.TargetRef == "" {
				add(v.ID, "target_ref", "required")
			} else if !ids[v.TargetRef] {
				add(v.ID, "target_ref", fmt.Sprintf("%q does not resolve to any object in this bundle", v.TargetRef))
			}
		}
	}

	return errs
}

// officialSchemaValidate validates the bundle against the official OASIS STIX 2.1
// JSON schema embedded in the binary.
func officialSchemaValidate(b Bundle) []ValidationError {
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020

	// Register every schema file by its $id so relative $ref resolution works.
	if err := registerSchemas(compiler); err != nil {
		return []ValidationError{{ObjectID: "(validator)", Field: "schema", Message: "failed to load STIX schemas: " + err.Error()}}
	}

	sch, err := compiler.Compile(bundleSchemaID)
	if err != nil {
		return []ValidationError{{ObjectID: "(validator)", Field: "schema", Message: "failed to compile bundle schema: " + err.Error()}}
	}

	bundleJSON, err := json.Marshal(b)
	if err != nil {
		return []ValidationError{{ObjectID: "(validator)", Field: "json", Message: "failed to marshal bundle: " + err.Error()}}
	}

	// Unmarshal into any so jsonschema v5 sees plain Go types (maps/slices), not structs.
	var doc any
	if err := json.Unmarshal(bundleJSON, &doc); err != nil {
		return []ValidationError{{ObjectID: "(validator)", Field: "json", Message: "failed to unmarshal bundle: " + err.Error()}}
	}

	if err := sch.Validate(doc); err != nil {
		return schemaErrorsToValidationErrors(err)
	}

	return nil
}

// registerSchemas walks the embedded stix schema FS, reads each JSON file's $id,
// and registers it with the compiler so relative $ref resolution works without network access.
func registerSchemas(compiler *jsonschema.Compiler) error {
	return fs.WalkDir(dragschema.StixFS, "stix", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}

		data, err := fs.ReadFile(dragschema.StixFS, path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		var meta struct {
			ID string `json:"$id"`
		}
		if err := json.Unmarshal(data, &meta); err != nil || meta.ID == "" {
			return nil // skip files without $id
		}

		return compiler.AddResource(meta.ID, bytes.NewReader(data))
	})
}

// schemaErrorsToValidationErrors converts jsonschema validation errors into our type.
func schemaErrorsToValidationErrors(err error) []ValidationError {
	var ve *jsonschema.ValidationError
	if ve == nil {
		// Try type assertion
		if v, ok := err.(*jsonschema.ValidationError); ok {
			ve = v
		}
	}

	if ve == nil {
		return []ValidationError{{ObjectID: "(bundle)", Field: "schema", Message: err.Error()}}
	}

	var out []ValidationError
	collectSchemaErrors(ve, &out)
	return out
}

func collectSchemaErrors(ve *jsonschema.ValidationError, out *[]ValidationError) {
	if len(ve.Causes) == 0 {
		*out = append(*out, ValidationError{
			ObjectID: "(bundle)",
			Field:    ve.InstanceLocation,
			Message:  ve.Message,
		})
		return
	}
	for _, cause := range ve.Causes {
		collectSchemaErrors(cause, out)
	}
}

func checkCommon(c Common, add func(id, field, msg string)) {
	if c.Type == "" {
		add(c.ID, "type", "required")
	}
	if c.ID == "" {
		add("(unknown)", "id", "required")
		return
	}
	expectedPrefix := c.Type + "--"
	if len(c.ID) < len(expectedPrefix)+36 {
		add(c.ID, "id", "too short to be a valid STIX ID")
	} else {
		suffix := c.ID[len(expectedPrefix):]
		if !uuidRE.MatchString(suffix) {
			add(c.ID, "id", fmt.Sprintf("UUID portion %q is not valid lowercase UUID4", suffix))
		}
	}
	if c.SpecVersion != "2.1" {
		add(c.ID, "spec_version", fmt.Sprintf("expected '2.1', got %q", c.SpecVersion))
	}
	if c.Created.IsZero() {
		add(c.ID, "created", "required and must be non-zero")
	}
	if c.Modified.IsZero() {
		add(c.ID, "modified", "required and must be non-zero")
	}
}
