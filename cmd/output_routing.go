// Package cmd: output routing helpers for the v0.1.11 3-repo distribution
// split (haul + haul-rules + haul-stix).
//
// Both `sync` and `generate` honour the optional --rules-root and --stix-root
// flags. When set, rule files and STIX bundles get written under those
// alternate roots (preserving the {module}/rules/... and {module}/feeds/stix/
// shape, just at a different parent). When unset, output goes inline next to
// the intel data (v0.1.10 behaviour, preserved for local development).
//
// The helpers below centralise the routing decision so each call site stays
// readable. Use `moduleRulesDir`, `moduleSTIXDir`, and `rootSTIXDir` instead
// of hand-building the paths.
package cmd

import "path/filepath"

// moduleRulesDir returns where rule files (sigma sources + compiled-backend
// outputs) for a given module should be written. moduleOutputDir is the
// per-module intel root (e.g. "supply"); its basename becomes the module
// segment under rulesRoot when --rules-root is set.
//
// Examples (moduleOutputDir = "supply"):
//   rulesRoot=""               → "supply/rules"
//   rulesRoot="/tmp/haul-rules" → "/tmp/haul-rules/supply/rules"
func moduleRulesDir(rulesRoot, moduleOutputDir string) string {
	if rulesRoot != "" {
		return filepath.Join(rulesRoot, filepath.Base(moduleOutputDir), "rules")
	}
	return filepath.Join(moduleOutputDir, "rules")
}

// compiledRootForBackend returns the module output root for a single backend
// when using the per-backend satellite split (--compiled-root-base).
//
// Examples (compiledRootBase = "../haul-rules", backendName = "kql", moduleOutputDir = "supply"):
//   → "../haul-rules-kql/supply/rules"
func compiledRootForBackend(compiledRootBase, backendName, moduleOutputDir string) string {
	return filepath.Join(compiledRootBase+"-"+backendName, filepath.Base(moduleOutputDir), "rules")
}

// moduleSTIXDir returns where the per-module STIX bundle should be written.
// Same shape as moduleRulesDir but for STIX output.
//
// Examples (moduleOutputDir = "supply"):
//   stixRoot=""                → "supply/feeds/stix"
//   stixRoot="/tmp/haul-stix"  → "/tmp/haul-stix/supply/feeds/stix"
func moduleSTIXDir(stixRoot, moduleOutputDir string) string {
	if stixRoot != "" {
		return filepath.Join(stixRoot, filepath.Base(moduleOutputDir), "feeds", "stix")
	}
	return filepath.Join(moduleOutputDir, "feeds", "stix")
}

// rootSTIXDir returns where the combined cross-module STIX bundle should be
// written. Mirrors the per-module helper but for the root bundle.
//
// Examples:
//   stixRoot=""                → "feeds/stix"
//   stixRoot="/tmp/haul-stix"  → "/tmp/haul-stix/feeds/stix"
func rootSTIXDir(stixRoot string) string {
	if stixRoot != "" {
		return filepath.Join(stixRoot, "feeds", "stix")
	}
	return filepath.Join("feeds", "stix")
}
