package ioc

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

// isValidIP returns true when s is a syntactically valid IPv4 or IPv6 address.
func isValidIP(s string) bool { return net.ParseIP(s) != nil }

// isLikelyDomain returns true when s looks like a hostname and is not an IP.
// Rejects anything containing spaces, ports, or path characters.
func isLikelyDomain(s string) bool {
	if net.ParseIP(s) != nil {
		return false
	}
	return strings.ContainsRune(s, '.') && !strings.ContainsAny(s, " \t:/\\@,;=")
}

// Exporter writes plain-text and unified JSON IOC feed files.
// Output files: domains.txt, ips.txt, sha256.txt, sha1.txt, md5.txt, unified.json
type Exporter struct{}

func New() *Exporter { return &Exporter{} }

// Export appends all IOCs from the incident into the feed files in dir.
// Existing entries are deduplicated.
func (e *Exporter) Export(inc *incident.Incident, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Collect domains — reject bare IPs and malformed values.
	// If a parser incorrectly classifies an IP as a domain, move it to IPs.
	var domains, promoIPs []string
	for _, d := range inc.Indicators.Domains {
		if net.ParseIP(d.Value) != nil {
			promoIPs = append(promoIPs, d.Value)
		} else if isLikelyDomain(d.Value) {
			domains = append(domains, d.Value)
		}
	}
	if err := appendLines(filepath.Join(dir, "domains.txt"), domains); err != nil {
		return fmt.Errorf("domains.txt: %w", err)
	}

	// Collect IPs — only syntactically valid addresses.
	var ips []string
	for _, ip := range inc.Indicators.IPs {
		if isValidIP(ip.Value) {
			ips = append(ips, ip.Value)
		}
	}
	ips = append(ips, promoIPs...)
	if err := appendLines(filepath.Join(dir, "ips.txt"), ips); err != nil {
		return fmt.Errorf("ips.txt: %w", err)
	}

	// Collect hashes by algorithm
	hashes := map[string][]string{}
	for _, h := range inc.Indicators.FileHashes {
		algo := strings.ToLower(h.Algorithm)
		hashes[algo] = append(hashes[algo], h.Value)
	}
	for _, algo := range []string{"sha256", "sha1", "md5"} {
		fname := algo + ".txt"
		if err := appendLines(filepath.Join(dir, fname), hashes[algo]); err != nil {
			return fmt.Errorf("%s: %w", fname, err)
		}
	}

	// Unified JSON
	return appendUnified(filepath.Join(dir, "unified.json"), inc)
}

// ContainerImageEntry is one record in the container-images.json feed.
type ContainerImageEntry struct {
	Type       string   `json:"type"`
	Repository string   `json:"repository"`
	Tag        string   `json:"tag"`
	OSFamily   string   `json:"os_family,omitempty"`
	CVEIDs     []string `json:"cve_ids,omitempty"`
	Tier       int      `json:"tier,omitempty"`
	IncidentID string   `json:"incident_id"`
	Confidence float64  `json:"confidence,omitempty"`
}

// ExportContainerImages writes or appends to {dir}/container-images.json for incidents
// with ContainerExt set. Traditional IOC feeds are skipped for container incidents.
func (e *Exporter) ExportContainerImages(inc *incident.Incident, dir string) error {
	if inc.ContainerExt == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	path := filepath.Join(dir, "container-images.json")

	// Load existing entries.
	var entries []ContainerImageEntry
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &entries)
	}

	// Index existing entries to avoid duplicates.
	type key struct{ repo, tag, incidentID string }
	existing := make(map[key]bool, len(entries))
	for _, e := range entries {
		existing[key{e.Repository, e.Tag, e.IncidentID}] = true
	}

	for _, img := range inc.ContainerExt.AffectedImages {
		for _, tag := range img.VulnerableTags {
			k := key{img.Repository, tag, inc.ID}
			if existing[k] {
				continue
			}
			existing[k] = true
			entries = append(entries, ContainerImageEntry{
				Type:       "container_image",
				Repository: img.Repository,
				Tag:        tag,
				OSFamily:   img.OSFamily,
				CVEIDs:     img.CVEIDs,
				Tier:       inc.ContainerExt.Tier,
				IncidentID: inc.ID,
				Confidence: img.Confidence,
			})
		}
	}
	for _, eol := range inc.ContainerExt.EOLImages {
		k := key{eol.Repository, eol.Cycle, inc.ID}
		if existing[k] {
			continue
		}
		existing[k] = true
		entries = append(entries, ContainerImageEntry{
			Type:       "container_image_eol",
			Repository: eol.Repository,
			Tag:        eol.Cycle,
			Tier:       inc.ContainerExt.Tier,
			IncidentID: inc.ID,
		})
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal container-images: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// appendLines reads existing lines, merges new ones, deduplicates, sorts, and writes.
func appendLines(path string, newLines []string) error {
	if len(newLines) == 0 {
		return nil
	}

	existing := readLines(path)
	merged := dedup(append(existing, newLines...))
	sort.Strings(merged)

	return os.WriteFile(path, []byte(strings.Join(merged, "\n")+"\n"), 0o644)
}

func readLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// UnifiedEntry is a single IOC record in unified.json.
type UnifiedEntry struct {
	Type       string   `json:"type"`
	Value      string   `json:"value"`
	IncidentID string   `json:"incident_id"`
	Sources    []string `json:"sources,omitempty"`
	Confidence float64  `json:"confidence,omitempty"`
	Filename   string   `json:"filename,omitempty"`
	Algorithm  string   `json:"algorithm,omitempty"`
}

// CombinedEntry is a single IOC record in the root combined feeds/unified.json.
// It tracks all modules and incidents that reference the same IOC.
type CombinedEntry struct {
	Type        string   `json:"type"`
	Value       string   `json:"value"`
	Modules     []string `json:"modules"`
	Confidence  float64  `json:"confidence,omitempty"`
	Incidents   []string `json:"incidents,omitempty"`
	CrossDomain bool     `json:"cross_domain,omitempty"`
}

// ExportCombined reads per-module unified.json files and writes root combined feeds.
// modules maps module name → feed directory (e.g. "supply" → "supply/feeds").
// destDir is the root feeds/ directory.
func ExportCombined(modules map[string]string, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}

	combined := map[string]*CombinedEntry{}

	for module, feedDir := range modules {
		data, err := os.ReadFile(filepath.Join(feedDir, "unified.json"))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("read %s unified.json: %w", module, err)
		}
		var entries []UnifiedEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			return fmt.Errorf("parse %s unified.json: %w", module, err)
		}
		for _, e := range entries {
			key := e.Type + "|" + e.Value
			ce, ok := combined[key]
			if !ok {
				ce = &CombinedEntry{Type: e.Type, Value: e.Value}
				combined[key] = ce
			}
			ce.Modules = uniqueStrings(ce.Modules, module)
			ce.Incidents = uniqueStrings(ce.Incidents, e.IncidentID)
			if e.Confidence > ce.Confidence {
				ce.Confidence = e.Confidence
			}
		}
	}

	var allEntries []CombinedEntry
	var domains, ips, sha256s []string
	for _, ce := range combined {
		if len(ce.Modules) > 1 {
			ce.CrossDomain = true
		}
		allEntries = append(allEntries, *ce)
		switch ce.Type {
		case "domain":
			domains = append(domains, ce.Value)
		case "ip":
			ips = append(ips, ce.Value)
		case "sha256":
			sha256s = append(sha256s, ce.Value)
		}
	}

	if err := appendLines(filepath.Join(destDir, "domains.txt"), domains); err != nil {
		return fmt.Errorf("combined domains.txt: %w", err)
	}
	if err := appendLines(filepath.Join(destDir, "ips.txt"), ips); err != nil {
		return fmt.Errorf("combined ips.txt: %w", err)
	}
	if err := appendLines(filepath.Join(destDir, "sha256.txt"), sha256s); err != nil {
		return fmt.Errorf("combined sha256.txt: %w", err)
	}

	data, err := json.MarshalIndent(allEntries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(destDir, "unified.json"), data, 0o644)
}

func uniqueStrings(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func appendUnified(path string, inc *incident.Incident) error {
	// Load existing entries
	var entries []UnifiedEntry
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &entries)
	}

	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Type+"|"+e.Value+"|"+e.IncidentID] = true
	}

	add := func(e UnifiedEntry) {
		key := e.Type + "|" + e.Value + "|" + e.IncidentID
		if !seen[key] {
			seen[key] = true
			entries = append(entries, e)
		}
	}

	for _, d := range inc.Indicators.Domains {
		if isLikelyDomain(d.Value) {
			add(UnifiedEntry{Type: "domain", Value: d.Value, IncidentID: inc.ID, Sources: d.Sources, Confidence: d.Confidence})
		} else if isValidIP(d.Value) {
			add(UnifiedEntry{Type: "ip", Value: d.Value, IncidentID: inc.ID, Sources: d.Sources, Confidence: d.Confidence})
		}
	}
	for _, ip := range inc.Indicators.IPs {
		if isValidIP(ip.Value) {
			add(UnifiedEntry{Type: "ip", Value: ip.Value, IncidentID: inc.ID, Sources: ip.Sources, Confidence: ip.Confidence})
		}
	}
	for _, u := range inc.Indicators.URLs {
		add(UnifiedEntry{Type: "url", Value: u.Value, IncidentID: inc.ID, Sources: u.Sources, Confidence: u.Confidence})
	}
	for _, h := range inc.Indicators.FileHashes {
		add(UnifiedEntry{
			Type:       h.Algorithm,
			Value:      h.Value,
			IncidentID: inc.ID,
			Sources:    h.Sources,
			Confidence: h.Confidence,
			Filename:   h.Filename,
			Algorithm:  h.Algorithm,
		})
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
