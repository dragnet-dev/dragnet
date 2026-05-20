package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/invopop/jsonschema"
	"github.com/spf13/cobra"
)

var schemaCmd = &cobra.Command{
	Use:   "schema",
	Short: "Generate the JSON Schema for incident records and write it to disk",
	Long: `Reflects the Go incident.Incident struct into a JSON Schema document.

Run after any struct change to keep schema/incident.schema.json in sync:

  dragnet schema                                    # update the embedded schema
  dragnet schema --output schema/incident.schema.json   # explicit path
  dragnet schema --output -                         # stdout

The haul workflow runs this automatically so haul/schema/incident.schema.json
is always current and consumable by third-party tools via raw GitHub URL.`,
	RunE: runSchema,
}

var schemaOutput string

func init() {
	schemaCmd.Flags().StringVar(&schemaOutput, "output", "schema/incident.schema.json",
		"File path to write the generated schema, or - for stdout")
	rootCmd.AddCommand(schemaCmd)
}

func runSchema(_ *cobra.Command, _ []string) error {
	r := &jsonschema.Reflector{
		AllowAdditionalProperties: true,
		DoNotReference:            false,
		ExpandedStruct:            false,
	}

	// Add descriptions for key fields via jsonschema struct tags where the
	// Go field names alone don't carry enough context for API consumers.
	schema := r.Reflect(&incident.Incident{})
	schema.ID = "https://github.com/dragnet-dev/dragnet/schema/incident.schema.json"
	schema.Title = "Dragnet Incident"
	schema.Description = "A Dragnet security incident record. " +
		"Produced by dragnet sync and consumed by port, buoy, scope, and third-party SIEM integrations. " +
		"Schema is auto-generated from internal/incident/schema.go — do not edit by hand."

	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if schemaOutput == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}

	if err := os.MkdirAll(filepath.Dir(schemaOutput), 0o755); err != nil {
		return err
	}
	return os.WriteFile(schemaOutput, data, 0o644)
}
