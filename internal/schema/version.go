// Package schema holds the canonical SchemaVersion constant shared across all
// dragnet output artifacts (index.json, manifest.json, etc.).
//
// Bump on breaking changes (field renamed or removed). Additive changes
// (new optional field) do not require a bump. All haul consumers (buoy,
// scope, trawl, port, dredge) check this value before parsing artifacts.
//
// When a new major version lands, output both the old and new version
// directories side-by-side (e.g. incidents/v1/ and incidents/v2/) for a
// deprecation window before dropping the old path.
package schema

// Version is the current haul schema version.
const Version = "1.0"
