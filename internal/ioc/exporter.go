package ioc

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/deconflict"
	"github.com/dragnet-dev/dragnet/internal/incident"
	"golang.org/x/net/publicsuffix"
)

// isPublicIP returns true when s is a syntactically valid IPv4 or IPv6 address
// AND is not in any allowlisted range (loopback, RFC1918, link-local, AWS IMDS).
// Without the deconflict check the feed would contain noise like 127.0.0.1
// and 169.254.169.254 leaked through from CVE proof-of-concept code samples.
func isPublicIP(s string) bool {
	if net.ParseIP(s) == nil {
		return false
	}
	return !deconflict.IP(s)
}

// validTLD matches the last DNS label: 2-24 lowercase letters. This rejects
// the garbage values that occasionally slip out of blog table parsers, where
// the IOC value gets concatenated with the type tag — e.g. `proton.meThreat`,
// `-IP142.11.206.73C2`, `07d889e2…c766Domainsfrclak.comC2`. None of those
// have a clean lowercase-letter TLD.
func isLikelyDomain(s string) bool {
	if s != strings.ToLower(s) {
		return false
	}
	if net.ParseIP(s) != nil {
		return false
	}
	if !strings.ContainsRune(s, '.') || strings.ContainsAny(s, " \t:/\\@,;=") {
		return false
	}
	tld := s[strings.LastIndex(s, ".")+1:]
	if len(tld) < 2 || len(tld) > 24 {
		return false
	}
	for _, c := range tld {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	if deconflict.Domain(s) {
		return false
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(s); err != nil {
		return false
	}
	return true
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
	if err := appendDomainLines(filepath.Join(dir, "domains.txt"), domains); err != nil {
		return fmt.Errorf("domains.txt: %w", err)
	}

	// Collect IPs — only syntactically valid, publicly-routable addresses.
	var ips []string
	for _, ip := range inc.Indicators.IPs {
		if isPublicIP(ip.Value) {
			ips = append(ips, ip.Value)
		}
	}
	for _, ip := range promoIPs {
		if isPublicIP(ip) {
			ips = append(ips, ip)
		}
	}
	if err := appendIPLines(filepath.Join(dir, "ips.txt"), ips); err != nil {
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

func appendDomainLines(path string, newLines []string) error {
	return appendFilteredLines(path, newLines, isLikelyDomain)
}

func appendIPLines(path string, newLines []string) error {
	return appendFilteredLines(path, newLines, isPublicIP)
}

func appendFilteredLines(path string, newLines []string, keep func(string) bool) error {
	existing := readLines(path)
	if len(existing) == 0 && len(newLines) == 0 {
		return nil
	}
	var filtered []string
	for _, line := range append(existing, newLines...) {
		if keep(line) {
			filtered = append(filtered, line)
		}
	}
	merged := dedup(filtered)
	sort.Strings(merged)
	if len(merged) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
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
			if !isValidUnifiedEntry(e) {
				continue
			}
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

	if err := appendDomainLines(filepath.Join(destDir, "domains.txt"), domains); err != nil {
		return fmt.Errorf("combined domains.txt: %w", err)
	}
	if err := appendIPLines(filepath.Join(destDir, "ips.txt"), ips); err != nil {
		return fmt.Errorf("combined ips.txt: %w", err)
	}
	if err := appendLines(filepath.Join(destDir, "sha256.txt"), sha256s); err != nil {
		return fmt.Errorf("combined sha256.txt: %w", err)
	}

	// Deterministic order before write — map iteration is random otherwise.
	sort.Slice(allEntries, func(i, j int) bool {
		if allEntries[i].Type != allEntries[j].Type {
			return allEntries[i].Type < allEntries[j].Type
		}
		return allEntries[i].Value < allEntries[j].Value
	})

	data, err := json.MarshalIndent(allEntries, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(destDir, "unified.json"), data, 0o644); err != nil {
		return err
	}
	// JSONL companion — same data, one entry per line, for stream/grep.
	return writeCombinedJSONL(filepath.Join(destDir, "unified.jsonl"), allEntries)
}

func writeCombinedJSONL(path string, entries []CombinedEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for i := range entries {
		if err := enc.Encode(entries[i]); err != nil {
			return err
		}
	}
	return nil
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
	entries = filterUnifiedEntries(entries)

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
		} else if isPublicIP(d.Value) {
			add(UnifiedEntry{Type: "ip", Value: d.Value, IncidentID: inc.ID, Sources: d.Sources, Confidence: d.Confidence})
		}
	}
	for _, ip := range inc.Indicators.IPs {
		if isPublicIP(ip.Value) {
			add(UnifiedEntry{Type: "ip", Value: ip.Value, IncidentID: inc.ID, Sources: ip.Sources, Confidence: ip.Confidence})
		}
	}
	for _, u := range inc.Indicators.URLs {
		if !deconflict.URL(u.Value) {
			add(UnifiedEntry{Type: "url", Value: u.Value, IncidentID: inc.ID, Sources: u.Sources, Confidence: u.Confidence})
		}
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
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	// Also write a stream/grep-friendly JSONL alongside unified.json so
	// consumers don't have to parse a multi-MB JSON array to scan the feed.
	return writeUnifiedJSONL(strings.TrimSuffix(path, ".json")+".jsonl", entries)
}

func filterUnifiedEntries(entries []UnifiedEntry) []UnifiedEntry {
	out := entries[:0]
	for _, entry := range entries {
		if isValidUnifiedEntry(entry) {
			out = append(out, entry)
		}
	}
	return out
}

func isValidUnifiedEntry(entry UnifiedEntry) bool {
	switch strings.ToLower(entry.Type) {
	case "domain":
		return isLikelyDomain(entry.Value)
	case "ip":
		return isPublicIP(entry.Value)
	case "url":
		return !deconflict.URL(entry.Value)
	default:
		return true
	}
}

// writeUnifiedJSONL serialises one UnifiedEntry per line, sorted for
// determinism. Order: type, then value, then incident_id.
func writeUnifiedJSONL(path string, entries []UnifiedEntry) error {
	sorted := make([]UnifiedEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Type != sorted[j].Type {
			return sorted[i].Type < sorted[j].Type
		}
		if sorted[i].Value != sorted[j].Value {
			return sorted[i].Value < sorted[j].Value
		}
		return sorted[i].IncidentID < sorted[j].IncidentID
	})
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for i := range sorted {
		if err := enc.Encode(sorted[i]); err != nil {
			return err
		}
	}
	return nil
}
