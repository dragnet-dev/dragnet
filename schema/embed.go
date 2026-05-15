package schema

import "embed"

//go:embed incident.schema.json
var IncidentJSON []byte

//go:embed stix
var StixFS embed.FS
