package sigma

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template" //nolint:gosec // nosemgrep: go.lang.security.audit.xss.import-text-template.import-text-template -- generating YAML, not HTML; html/template would corrupt template syntax
	"time"

	"github.com/dragnet-dev/dragnet/internal/confidence"
	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/dragnet-dev/dragnet/internal/iocutil"
	"github.com/google/uuid"
)

const sigmaNamespace = "dragnet:"

// normalizeIOCValue is the canonical IOC cleaner; it lives in
// internal/iocutil and is shared with the blog parsers (see
// internal/sources/blogs/generic.go) to keep the same allowlist behaviour.
var normalizeIOCValue = iocutil.Normalize

const maxReferences = 15

func refTier(ref string) int {
	switch {
	case strings.Contains(ref, "cisa.gov"),
		strings.Contains(ref, "nvd.nist.gov"),
		strings.Contains(ref, "osv.dev"):
		return 0
	case strings.Contains(ref, "aikido.dev"),
		strings.Contains(ref, "stepsecurity.io"),
		strings.Contains(ref, "wiz.io"),
		strings.Contains(ref, "socket.dev"),
		strings.Contains(ref, "bleepingcomputer.com"),
		strings.Contains(ref, "thehackernews.com"),
		strings.Contains(ref, "securelist.com"),
		strings.Contains(ref, "sentinelone.com"),
		strings.Contains(ref, "unit42.paloalto"),
		strings.Contains(ref, "mandiant.com"),
		strings.Contains(ref, "crowdstrike.com"):
		return 1
	case strings.Contains(ref, "github.com/advisories"),
		strings.Contains(ref, "github.com/security/advisories"):
		return 2
	case strings.Contains(ref, "github.com"):
		return 3
	default:
		return 4
	}
}

func truncateReferences(refs []string) []string {
	if len(refs) <= maxReferences {
		return refs
	}
	sorted := make([]string, len(refs))
	copy(sorted, refs)
	sort.SliceStable(sorted, func(i, j int) bool {
		return refTier(sorted[i]) < refTier(sorted[j])
	})
	return sorted[:maxReferences]
}

// Generator produces Sigma rule files from an incident.
type Generator struct {
	OutputDir string    // root of rules/sigma/
	Module    string    // supply/malware/ransomware/cve — used in Dragnet IDs
	Registry  *Registry // assigns sequential dragnet-<module>-<year>-<NNNN> IDs
}

// New creates a Generator that writes rules under outputDir.
func New(outputDir, module string, registry *Registry) *Generator {
	return &Generator{OutputDir: outputDir, Module: module, Registry: registry}
}

// templateFuncs is the FuncMap available in every template.
var templateFuncs = template.FuncMap{
	"upper": strings.ToUpper,
	// yamlsq escapes a string for safe embedding inside YAML single-quoted
	// context: `'{{ yamlsq .Value }}'`. The only escape in YAML's
	// single-quoted form is doubling the quote character — newlines and
	// other control chars stay literal (we already flatten those at
	// ingest, see ransomware_live.flattenWS). Without this, URLs that
	// encode victim names like "company's_part1" prematurely close the
	// YAML string and break every downstream backend's parser.
	"yamlsq": func(s string) string {
		return strings.ReplaceAll(s, "'", "''")
	},
	"networkCondition": func(d TemplateData) string {
		parts := []string{}
		if len(d.Domains) > 0 {
			parts = append(parts, "selection_domain")
		}
		if len(d.IPs) > 0 {
			parts = append(parts, "selection_ip")
		}
		if len(d.URLs) > 0 {
			parts = append(parts, "selection_url")
		}
		if len(parts) == 0 {
			return "selection"
		}
		return strings.Join(parts, " or ")
	},
	"persistenceCondition": func(d TemplateData) string {
		parts := []string{}
		if len(d.ServiceNames) > 0 {
			parts = append(parts, "selection_service")
		}
		if len(d.MacOSPersistence) > 0 {
			parts = append(parts, "selection_macos")
		}
		if len(d.LinuxPersistence) > 0 {
			parts = append(parts, "selection_linux")
		}
		if len(parts) == 0 {
			return "selection"
		}
		return strings.Join(parts, " or ")
	},
	"sessionCondition": func(d TemplateData) string {
		parts := []string{}
		if len(d.SessionSeedNodes) > 0 {
			parts = append(parts, "selection_seed")
		}
		if d.SessionFileServer != "" {
			parts = append(parts, "selection_fileserver")
		}
		if d.SessionRecipientID != "" {
			parts = append(parts, "selection_recipient")
		}
		if len(parts) == 0 {
			return "selection"
		}
		return strings.Join(parts, " or ")
	},
	// imageTagList expands AffectedImages into "repo:tag" strings for container templates.
	"imageTagList": func(imgs []ContainerImageTmplData) []string {
		var out []string
		for _, img := range imgs {
			for _, tag := range img.VulnerableTags {
				out = append(out, img.Repository+":"+tag)
			}
		}
		return out
	},
}

// loadTemplate parses a template from the embedded FS.
func loadTemplate(path string) (*template.Template, error) {
	content, err := templateFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading template %s: %w", path, err)
	}
	tmpl, err := template.New(filepath.Base(path)).Funcs(templateFuncs).Parse(string(content))
	if err != nil {
		return nil, fmt.Errorf("parsing template %s: %w", path, err)
	}
	return tmpl, nil
}

// render executes a template and returns the result as a string.
func render(tmpl *template.Template, data TemplateData) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// writeRule renders a template and writes the result to outputDir/subdir/filename.
// Skips the write when the existing file's bytes already match — avoids
// dirtying git's index on stable rules across consecutive runs.
func (g *Generator) writeRule(tmplPath, subdir, filename string, data TemplateData) error {
	tmpl, err := loadTemplate(tmplPath)
	if err != nil {
		return err
	}
	content, err := render(tmpl, data)
	if err != nil {
		return fmt.Errorf("rendering %s: %w", tmplPath, err)
	}
	dir := filepath.Join(g.OutputDir, subdir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}
	outPath := filepath.Join(dir, filename)
	newBytes := []byte(content)
	if existing, err := os.ReadFile(outPath); err == nil && bytes.Equal(existing, newBytes) {
		return nil
	}
	if err := os.WriteFile(outPath, newBytes, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", outPath, err)
	}
	return nil
}

// Generate produces all Sigma rules for the given incident across all layers.
func (g *Generator) Generate(inc *incident.Incident) error {
	today := time.Now().Format("2006-01-02")
	base := g.buildBaseData(inc, today)

	// Layer 1 — Exposure (supply chain)
	if err := g.generateExposure(inc, base); err != nil {
		return err
	}

	// Layer 2 — IOC (network, hashes, persistence)
	if err := g.generateIOC(inc, base); err != nil {
		return err
	}

	// Layer 3 — Behavioural hunting
	if err := g.generateHunting(inc, base); err != nil {
		return err
	}

	// Domain-specific layers
	if inc.MalwareExt != nil {
		if err := g.generateMalware(inc, base); err != nil {
			return err
		}
	}
	if inc.RansomwareExt != nil {
		if err := g.generateRansomware(inc, base); err != nil {
			return err
		}
	}
	if inc.CVEExt != nil {
		if err := g.generateCVE(inc, base); err != nil {
			return err
		}
	}
	if inc.ContainerExt != nil {
		if err := g.generateContainer(inc, base); err != nil {
			return err
		}
	}

	// Supply-module ecosystem-specific rules (GitHub Actions, Hugging Face).
	if hasSupplyEcosystemRules(inc) {
		if err := g.generateSupply(inc, base); err != nil {
			return err
		}
	}

	return nil
}

// generateExposure writes Layer 1 rules.
func (g *Generator) generateExposure(inc *incident.Incident, base TemplateData) error {
	subdir := "exposure/" + base.Year
	if len(inc.Exposure.LockfileSignatures) > 0 {
		d := base
		d.ID = RuleID(inc.ID, "exposure", "lockfile").String()
		d.LockfileSignatures = inc.Exposure.LockfileSignatures
		if err := g.writeRule(
			"templates/exposure/lockfile.tmpl",
			subdir,
			base.DragnetID+"-exposure.yaml",
			d,
		); err != nil {
			return err
		}
	}

	if len(inc.Exposure.FilePresence) > 0 {
		d := base
		d.ID = RuleID(inc.ID, "exposure", "file_presence").String()
		d.FilePresence = inc.Exposure.FilePresence
		filename := base.DragnetID + "-exposure-file-presence.yaml"
		if len(inc.Exposure.LockfileSignatures) == 0 {
			filename = base.DragnetID + "-exposure.yaml"
		}
		if err := g.writeRule(
			"templates/exposure/file_presence.tmpl",
			subdir,
			filename,
			d,
		); err != nil {
			return err
		}
	}

	return nil
}

// generateIOC writes Layer 2 rules.
func (g *Generator) generateIOC(inc *incident.Incident, base TemplateData) error {
	if !hasHighConfidenceIOC(inc) {
		return nil
	}
	subdir := "ioc/" + base.Year

	// Network IOC
	if len(inc.Indicators.Domains) > 0 || len(inc.Indicators.IPs) > 0 || len(inc.Indicators.URLs) > 0 {
		d := base
		d.ID = RuleID(inc.ID, "ioc", "network").String()
		for _, v := range inc.Indicators.Domains {
			if clean, ok := normalizeIOCValue("domain", v.Value); ok {
				d.Domains = append(d.Domains, IOCValue{Value: clean, Confidence: v.Confidence})
			}
		}
		for _, v := range inc.Indicators.IPs {
			if clean, ok := normalizeIOCValue("ip", v.Value); ok {
				d.IPs = append(d.IPs, IOCValue{Value: clean, Confidence: v.Confidence})
			}
		}
		for _, v := range inc.Indicators.URLs {
			if clean, ok := normalizeIOCValue("url", v.Value); ok {
				d.URLs = append(d.URLs, IOCValue{Value: clean, Confidence: v.Confidence})
			}
		}
		if err := g.writeRule(
			"templates/ioc/network.tmpl",
			subdir,
			base.DragnetID+"-ioc-network.yaml",
			d,
		); err != nil {
			return err
		}
	}

	// File hashes
	if len(inc.Indicators.FileHashes) > 0 {
		d := base
		d.ID = RuleID(inc.ID, "ioc", "hashes").String()
		for _, h := range inc.Indicators.FileHashes {
			d.FileHashes = append(d.FileHashes, HashValue{
				Algorithm:  h.Algorithm,
				Value:      h.Value,
				Filename:   h.Filename,
				Confidence: h.Confidence,
			})
		}
		if err := g.writeRule(
			"templates/ioc/file_hash.tmpl",
			subdir,
			base.DragnetID+"-ioc-hashes.yaml",
			d,
		); err != nil {
			return err
		}
	}

	// Persistence IOC
	if inc.Indicators.Persistence != nil {
		p := inc.Indicators.Persistence
		if len(p.ServiceNames) > 0 || len(p.MacOSLaunchAgent) > 0 || len(p.LinuxSystemd) > 0 {
			d := base
			d.ID = RuleID(inc.ID, "ioc", "persistence").String()
			d.ServiceNames = p.ServiceNames
			d.MacOSPersistence = p.MacOSLaunchAgent
			d.LinuxPersistence = p.LinuxSystemd
			if err := g.writeRule(
				"templates/ioc/persistence.tmpl",
				subdir,
				base.DragnetID+"-ioc-persistence.yaml",
				d,
			); err != nil {
				return err
			}
		}
	}

	// Session network
	if inc.Indicators.SessionNetwork != nil {
		sn := inc.Indicators.SessionNetwork
		if sn.RecipientID != "" || len(sn.SeedNodes) > 0 || sn.FileServer != "" {
			d := base
			d.ID = RuleID(inc.ID, "ioc", "session").String()
			d.SessionRecipientID = sn.RecipientID
			d.SessionSeedNodes = sn.SeedNodes
			d.SessionFileServer = sn.FileServer
			if err := g.writeRule(
				"templates/ioc/session_network.tmpl",
				subdir,
				base.DragnetID+"-ioc-session.yaml",
				d,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

// huntingTemplate maps a behaviour ID prefix to its template path.
func huntingTemplatePath(behID string) string {
	switch {
	case behID == "BEH-001":
		return "templates/hunting/proc_memory_read.tmpl"
	case behID == "BEH-002" || behID == "BEH-005" || behID == "BEH-007":
		return "templates/hunting/pkg_manager_network.tmpl"
	case behID == "BEH-003" || behID == "BEH-004":
		return "templates/hunting/persistence_creation.tmpl"
	case behID == "BEH-006":
		return "templates/hunting/destructive_command.tmpl"
	default:
		// Credential access / catch-all
		return "templates/hunting/credential_access.tmpl"
	}
}

// generateHunting writes Layer 3 rules.
func (g *Generator) generateHunting(inc *incident.Incident, base TemplateData) error {
	subdir := "hunting/" + base.Year
	for _, beh := range inc.Hunting.Behaviours {
		d := base
		d.ID = RuleID(inc.ID, "hunting", beh.ID).String()
		d.Behaviour = BehaviourData{
			ID:          beh.ID,
			Description: beh.Description,
			Platform:    beh.Platform,
		}
		tmplPath := huntingTemplatePath(beh.ID)
		filename := base.DragnetID + "-hunting-" + beh.ID + ".yaml"
		if err := g.writeRule(tmplPath, subdir, filename, d); err != nil {
			return err
		}
	}
	return nil
}

// attackTypeTag maps attack types to Dragnet-namespace Sigma tags.
var attackTypeTag = map[string]string{
	"account_takeover":    "dragnet.supply-chain",
	"typosquat":           "dragnet.supply-chain",
	"dep_confusion":       "dragnet.supply-chain",
	"poisoned_maintainer": "dragnet.supply-chain",
	"malicious_publish":   "dragnet.supply-chain",
	"ci_poisoning":        "dragnet.supply-chain",
	"namespace_squatting": "dragnet.supply-chain",
	"ransomware":          "dragnet.ransomware",
	"vulnerability":       "dragnet.cve",
	"exploit":             "dragnet.cve",
}

// buildBaseData constructs TemplateData fields shared across all rules for an incident.
func (g *Generator) buildBaseData(inc *incident.Incident, date string) TemplateData {
	// Parse first-seen date for confidence decay and year-subdir routing.
	var firstSeen time.Time
	if inc.CompromiseWindow.Start != "" {
		if t, err := time.Parse(time.RFC3339, inc.CompromiseWindow.Start); err == nil {
			firstSeen = t
		}
	}
	best := highestIOCConfidence(inc)
	decayed := confidence.Decay(best, firstSeen)

	year := time.Now().Format("2006")
	if !firstSeen.IsZero() {
		year = firstSeen.Format("2006")
	}

	// Post-v0.1.10: inc.ID is already canonical (assigned at ingest time via
	// the same registry, see cmd/sync.go assignCanonicalIDs). For backward
	// compatibility with incidents that pre-date the unification (loaded from
	// older shards without LegacyID set), still call AssignID — which is
	// idempotent for already-canonical IDs only if the registry knows them;
	// otherwise use LegacyID as the lookup key so the registry returns the
	// same canonical ID it minted at ingest.
	dragnetID := inc.ID
	if g.Registry != nil && !strings.HasPrefix(inc.ID, "dragnet-") {
		lookupKey := inc.ID
		if inc.LegacyID != "" {
			lookupKey = inc.LegacyID
		}
		dragnetID = g.Registry.AssignID(g.Module, lookupKey, firstSeen)
	}

	d := TemplateData{
		DragnetID:   dragnetID,
		IncidentID:  inc.ID,
		Year:        year,
		Module:      g.Module,
		Description: buildRichDescription(inc),
		Date:        date,
		References:  truncateReferences(inc.References),
		Level:       severityToLevel(inc.Severity),
		Status:      confidence.Status(decayed),
	}

	// MITRE ATT&CK tags
	for _, t := range inc.Hunting.MITRETechniques {
		tag := "attack." + strings.ToLower(strings.ReplaceAll(t.ID, ".", ""))
		d.Tags = append(d.Tags, tag)
	}

	// Dragnet module tag
	if tag, ok := attackTypeTag[inc.AttackType]; ok {
		d.Tags = appendUnique(d.Tags, tag)
	}
	// Actor/campaign tags — enable filtering by actor or campaign in SIEM
	if inc.Campaign.Actor != "" {
		d.Tags = appendUnique(d.Tags, "dragnet.actor."+tagSlug(inc.Campaign.Actor))
	}
	if inc.Campaign.Name != "" {
		d.Tags = appendUnique(d.Tags, "dragnet.campaign."+tagSlug(inc.Campaign.Name))
	}

	// Package metadata
	for _, pkg := range inc.Packages {
		d.PackageNames = append(d.PackageNames, pkg.Name)
		if pkg.Ecosystem != "" {
			d.Ecosystems = appendUnique(d.Ecosystems, pkg.Ecosystem)
		}
	}

	return d
}

// severityToLevel maps incident severity to a Sigma level string.
func severityToLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

// highestIOCConfidence returns the highest confidence value across all IOCs.
// Falls back to campaign confidence string when no IOC confidence is set.
func highestIOCConfidence(inc *incident.Incident) float64 {
	best := 0.0
	for _, v := range inc.Indicators.Domains {
		if v.Confidence > best {
			best = v.Confidence
		}
	}
	for _, v := range inc.Indicators.IPs {
		if v.Confidence > best {
			best = v.Confidence
		}
	}
	for _, v := range inc.Indicators.URLs {
		if v.Confidence > best {
			best = v.Confidence
		}
	}
	for _, h := range inc.Indicators.FileHashes {
		if h.Confidence > best {
			best = h.Confidence
		}
	}
	if best == 0.0 {
		switch strings.ToLower(inc.Campaign.Confidence) {
		case "high":
			best = 0.90
		case "medium":
			best = 0.70
		case "low":
			best = 0.40
		}
	}
	return best
}

const minIOCConfidence = 0.60

// hasHighConfidenceIOC returns true when at least one IOC meets the minimum threshold.
func hasHighConfidenceIOC(inc *incident.Incident) bool {
	for _, v := range inc.Indicators.Domains {
		if v.Confidence >= minIOCConfidence {
			return true
		}
	}
	for _, v := range inc.Indicators.IPs {
		if v.Confidence >= minIOCConfidence {
			return true
		}
	}
	for _, v := range inc.Indicators.URLs {
		if v.Confidence >= minIOCConfidence {
			return true
		}
	}
	for _, h := range inc.Indicators.FileHashes {
		if h.Confidence >= minIOCConfidence {
			return true
		}
	}
	return false
}

// buildRichDescription builds the supplementary portion of a Sigma rule description —
// actor/campaign context, first-observed date, and confidence/sources. The template
// already emits the incident ID on its own line; this function returns the lines that
// follow, joined with "\n  " to preserve YAML literal block scalar indentation.
func buildRichDescription(inc *incident.Incident) string {
	var parts []string

	switch {
	case inc.Campaign.Actor != "" && inc.Campaign.Name != "":
		parts = append(parts, fmt.Sprintf("Associated with %s (%s campaign).", inc.Campaign.Actor, inc.Campaign.Name))
	case inc.Campaign.Actor != "":
		parts = append(parts, fmt.Sprintf("Associated with %s.", inc.Campaign.Actor))
	case inc.Campaign.Name != "":
		parts = append(parts, fmt.Sprintf("Associated with %s campaign.", inc.Campaign.Name))
	}

	if len(inc.Description) > 10 && !strings.HasPrefix(inc.Description, "Incident: ") {
		// Defensive: collapse any internal whitespace so embedded
		// descriptions can't break the rule's YAML block scalar. The
		// ingest layer (ransomware_live, etc.) is the primary defence;
		// this catches anything that slips through.
		parts = append(parts, strings.Join(strings.Fields(inc.Description), " "))
	}

	if inc.CompromiseWindow.Start != "" {
		if t, err := time.Parse(time.RFC3339, inc.CompromiseWindow.Start); err == nil {
			parts = append(parts, "First observed: "+t.Format("2006-01-02")+".")
		}
	}

	allSources := inc.Sources
	if len(allSources) == 0 && inc.Source != "" {
		allSources = []string{inc.Source}
	}
	if best := highestIOCConfidence(inc); best > 0 && len(allSources) > 0 {
		parts = append(parts, fmt.Sprintf("Confidence: %.0f%% (%s).", best*100, strings.Join(allSources, ", ")))
	}

	// "\n  " preserves the 2-space indentation of the YAML literal block scalar.
	return strings.Join(parts, "\n  ")
}

// tagSlug converts a string to a lowercase hyphen-separated tag slug.
func tagSlug(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	prevHyphen := true
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevHyphen = false
		} else if !prevHyphen {
			b.WriteRune('-')
			prevHyphen = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// appendUnique appends s to slice only if not already present.
func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

// RuleID produces a deterministic UUID for a Sigma rule, stable across re-runs.
func RuleID(incidentID, layer, subtype string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL,
		[]byte(sigmaNamespace+incidentID+":"+layer+":"+subtype))
}

// generateMalware writes malware-module Sigma rules.
func (g *Generator) generateMalware(inc *incident.Incident, base TemplateData) error {
	ext := inc.MalwareExt
	subdir := "malware/" + base.Year

	base.MalwareFamily = ext.MalwareFamily
	base.MalwareType = ext.MalwareType

	if len(ext.Mutexes) > 0 {
		d := base
		d.ID = RuleID(inc.ID, "malware", "mutex").String()
		for _, m := range ext.Mutexes {
			d.Mutexes = append(d.Mutexes, m.Value)
		}
		if err := g.writeRule("templates/malware/mutex_detection.tmpl", subdir,
			base.DragnetID+"-malware-mutex.yaml", d); err != nil {
			return err
		}
	}

	if len(ext.NamedPipes) > 0 {
		d := base
		d.ID = RuleID(inc.ID, "malware", "named_pipe").String()
		for _, p := range ext.NamedPipes {
			d.NamedPipes = append(d.NamedPipes, p.Value)
		}
		if err := g.writeRule("templates/malware/named_pipe.tmpl", subdir,
			base.DragnetID+"-malware-named-pipe.yaml", d); err != nil {
			return err
		}
	}

	if len(ext.RegistryKeys) > 0 {
		d := base
		d.ID = RuleID(inc.ID, "malware", "registry").String()
		for _, r := range ext.RegistryKeys {
			d.RegistryKeys = append(d.RegistryKeys, r.Value)
		}
		if err := g.writeRule("templates/malware/registry_persistence.tmpl", subdir,
			base.DragnetID+"-malware-registry.yaml", d); err != nil {
			return err
		}
	}

	// Process injection — always write if there's a malware ext with a family name
	if ext.MalwareFamily != "" {
		d := base
		d.ID = RuleID(inc.ID, "malware", "proc_injection").String()
		if err := g.writeRule("templates/malware/process_injection.tmpl", subdir,
			base.DragnetID+"-malware-proc-injection.yaml", d); err != nil {
			return err
		}

		d.ID = RuleID(inc.ID, "malware", "cred_dump").String()
		if err := g.writeRule("templates/malware/credential_dumping.tmpl", subdir,
			base.DragnetID+"-malware-cred-dump.yaml", d); err != nil {
			return err
		}
	}

	return nil
}

// generateRansomware writes ransomware-module Sigma rules.
func (g *Generator) generateRansomware(inc *incident.Incident, base TemplateData) error {
	ext := inc.RansomwareExt
	subdir := "ransomware/" + base.Year
	base.RansomwareGroup = ext.RansomwareGroup
	base.RansomNoteFilenames = ext.RansomNoteFilenames
	for _, t := range ext.ToolsObserved {
		base.ToolNames = append(base.ToolNames, t.Name)
	}

	type ransomRule struct {
		tmpl    string
		subtype string
		suffix  string
		skip    func() bool
	}
	rules := []ransomRule{
		{"templates/ransomware/shadow_copy_deletion.tmpl", "shadow_copy", "-ran-shadow-copy.yaml", nil},
		{"templates/ransomware/recovery_inhibition.tmpl", "recovery_inhibit", "-ran-recovery-inhibit.yaml", nil},
		{"templates/ransomware/log_clearing.tmpl", "log_clear", "-ran-log-clear.yaml", nil},
		{"templates/ransomware/mass_file_rename.tmpl", "mass_rename", "-ran-mass-rename.yaml", nil},
		{"templates/ransomware/ransom_note_drop.tmpl", "ransom_note", "-ran-note-drop.yaml",
			func() bool { return len(ext.RansomNoteFilenames) == 0 }},
		{"templates/ransomware/exfil_tools.tmpl", "exfil_tools", "-ran-exfil-tools.yaml",
			func() bool { return len(ext.ToolsObserved) == 0 }},
	}

	for _, r := range rules {
		if r.skip != nil && r.skip() {
			continue
		}
		d := base
		d.ID = RuleID(inc.ID, "ransomware", r.subtype).String()
		if err := g.writeRule(r.tmpl, subdir, base.DragnetID+r.suffix, d); err != nil {
			return err
		}
	}
	return nil
}

// generateContainer writes container-module Sigma rules for vulnerable and EOL images.
func (g *Generator) generateContainer(inc *incident.Incident, base TemplateData) error {
	ext := inc.ContainerExt
	subdir := "container/" + base.Year
	base.ContainerCVSS = ext.CVSS
	base.ContainerTier = ext.Tier

	for _, img := range ext.AffectedImages {
		base.AffectedImages = append(base.AffectedImages, ContainerImageTmplData{
			Repository:     img.Repository,
			OSFamily:       img.OSFamily,
			VulnerableTags: img.VulnerableTags,
			FixedTag:       img.FixedTag,
		})
	}
	for _, eol := range ext.EOLImages {
		base.EOLImages = append(base.EOLImages, EOLImageTmplData{
			Repository:  eol.Repository,
			Cycle:       eol.Cycle,
			EOLDate:     eol.EOLDate,
			Replacement: eol.Replacement,
		})
	}

	if len(base.AffectedImages) > 0 {
		d := base
		d.ID = RuleID(inc.ID, "container", "vuln").String()
		if err := g.writeRule("templates/container/vulnerable_base_image.tmpl", subdir,
			base.DragnetID+"-container-vuln.yaml", d); err != nil {
			return err
		}
	}
	if len(base.EOLImages) > 0 {
		d := base
		d.ID = RuleID(inc.ID, "container", "eol").String()
		if err := g.writeRule("templates/container/eol_base_image.tmpl", subdir,
			base.DragnetID+"-container-eol.yaml", d); err != nil {
			return err
		}
	}
	return nil
}

// generateCVE writes CVE-module Sigma rules.
func (g *Generator) generateCVE(inc *incident.Incident, base TemplateData) error {
	ext := inc.CVEExt
	subdir := "cve/" + base.Year
	base.CVEID = ext.CVEID
	base.CVSSScore = ext.CVSSScore

	for _, h := range ext.HTTPIndicators {
		switch h.Type {
		case "user_agent":
			base.HTTPUserAgents = append(base.HTTPUserAgents, h.Value)
		case "url_pattern", "request_body_pattern":
			base.HTTPPatterns = append(base.HTTPPatterns, h.Value)
		}
	}

	if len(base.HTTPUserAgents) > 0 {
		d := base
		d.ID = RuleID(inc.ID, "cve", "scanner_ua").String()
		if err := g.writeRule("templates/cve/exploit_scanner_ua.tmpl", subdir,
			base.DragnetID+"-cve-scanner-ua.yaml", d); err != nil {
			return err
		}
	}

	if len(base.HTTPPatterns) > 0 {
		d := base
		d.ID = RuleID(inc.ID, "cve", "http_pattern").String()
		if err := g.writeRule("templates/cve/http_exploit_pattern.tmpl", subdir,
			base.DragnetID+"-cve-http-pattern.yaml", d); err != nil {
			return err
		}
	}

	// Web shell and post-exploit rules are always generated for CVE incidents
	if ext.CVEID != "" {
		for _, rule := range []struct {
			tmpl    string
			subtype string
			suffix  string
		}{
			{"templates/cve/web_shell_creation.tmpl", "web_shell", "-cve-web-shell.yaml"},
			{"templates/cve/web_server_outbound.tmpl", "web_outbound", "-cve-web-outbound.yaml"},
			{"templates/cve/post_exploit_download.tmpl", "post_exploit", "-cve-post-exploit.yaml"},
		} {
			d := base
			d.ID = RuleID(inc.ID, "cve", rule.subtype).String()
			if err := g.writeRule(rule.tmpl, subdir, base.DragnetID+rule.suffix, d); err != nil {
				return err
			}
		}
	}

	return nil
}

// hasSupplyEcosystemRules returns true when an incident has packages in an
// ecosystem that has dedicated supply-module Sigma templates.
func hasSupplyEcosystemRules(inc *incident.Incident) bool {
	for _, pkg := range inc.Packages {
		switch pkg.Ecosystem {
		case "github-actions", "huggingface":
			return true
		}
	}
	return false
}

// generateSupply writes supply-module ecosystem-specific Sigma rules for
// GitHub Actions and Hugging Face incidents.
func (g *Generator) generateSupply(inc *incident.Incident, base TemplateData) error {
	for _, pkg := range inc.Packages {
		switch pkg.Ecosystem {
		case "github-actions":
			if err := g.writeGitHubActionsRules(inc, pkg.Name, base); err != nil {
				return err
			}
		case "huggingface":
			if err := g.writeHuggingFaceRules(inc, pkg.Name, base); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *Generator) writeGitHubActionsRules(inc *incident.Incident, actionName string, base TemplateData) error {
	subdir := "supply/github_actions/" + base.Year
	d := base
	d.ActionName = actionName

	for _, wi := range inc.Indicators.WorkflowIndicators {
		d.WorkflowIndicators = append(d.WorkflowIndicators, WorkflowIndicatorTmplData{
			Type:  wi.Type,
			Value: wi.Value,
		})
	}

	d.ID = RuleID(inc.ID, "supply", "github_actions_compromised").String()
	if err := g.writeRule("templates/supply/github_actions/compromised_action.tmpl", subdir,
		base.DragnetID+"-supply-actions-compromised.yaml", d); err != nil {
		return err
	}

	return nil
}

func (g *Generator) writeHuggingFaceRules(inc *incident.Incident, modelName string, base TemplateData) error {
	subdir := "supply/huggingface/" + base.Year
	d := base
	d.ModelName = modelName

	for _, mi := range inc.Indicators.ModelIndicators {
		d.ModelIndicators = append(d.ModelIndicators, ModelIndicatorTmplData{
			Type:        mi.Type,
			Filename:    mi.Filename,
			Description: mi.Description,
		})
	}

	d.ID = RuleID(inc.ID, "supply", "hf_malicious_model").String()
	if err := g.writeRule("templates/supply/huggingface/malicious_model.tmpl", subdir,
		base.DragnetID+"-supply-hf-malicious.yaml", d); err != nil {
		return err
	}

	// Write format-downgrade rule only when that specific signal is present.
	for _, mi := range inc.Indicators.ModelIndicators {
		if mi.Type == "format_downgrade" {
			fd := d
			fd.ID = RuleID(inc.ID, "supply", "hf_format_downgrade").String()
			if err := g.writeRule("templates/supply/huggingface/safe_format_downgrade.tmpl", subdir,
				base.DragnetID+"-supply-hf-format-downgrade.yaml", fd); err != nil {
				return err
			}
			break
		}
	}

	return nil
}
