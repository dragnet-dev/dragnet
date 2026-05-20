package yara

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

const minConfidence = 0.7

var ruleNameSanitize = regexp.MustCompile(`[^a-zA-Z0-9_]`)

// Backend generates YARA rules directly from incident IOC data.
// It implements IOCNativeBackend — it does not compile Sigma YAML.
type Backend struct{}

func New() *Backend { return &Backend{} }

func (b *Backend) Name() string            { return "yara" }
func (b *Backend) OutputExtension() string { return ".yar" }

// GenerateFromIncident produces YARA rules for one incident.
// Combines:
//   - Source-provided rule bodies (from MalwareExt.YaraRules where Body != "")
//   - An IOC-generated rule derived from the incident's indicators (when any IOC passes the 0.7 confidence gate)
//
// Returns nil, nil when neither source bodies nor usable IOCs are present.
func (b *Backend) GenerateFromIncident(inc *incident.Incident) ([]byte, error) {
	var buf bytes.Buffer

	// Pass through source-provided rule bodies verbatim.
	if inc.MalwareExt != nil {
		for _, yr := range inc.MalwareExt.YaraRules {
			if yr.Body != "" {
				buf.WriteString(yr.Body)
				if !strings.HasSuffix(yr.Body, "\n") {
					buf.WriteByte('\n')
				}
				buf.WriteByte('\n')
			}
		}
	}

	// Generate IOC-based rule from indicators.
	iocRule, err := generateIOCRule(inc)
	if err != nil {
		return nil, err
	}
	if iocRule != nil {
		buf.Write(iocRule)
	}

	if buf.Len() == 0 {
		return nil, nil
	}
	return buf.Bytes(), nil
}

// generateIOCRule builds a YARA rule from the incident's indicators.
// Returns nil when no IOCs survive the confidence gate.
func generateIOCRule(inc *incident.Incident) ([]byte, error) {
	hashes := filterHashes(inc)
	domains := filterValues(inc.Indicators.Domains)
	ips := filterValues(inc.Indicators.IPs)
	paths := filterPaths(inc)

	if len(hashes)+len(domains)+len(ips)+len(paths) == 0 {
		return nil, nil
	}

	ruleName := "dragnet_ioc_" + ruleNameSanitize.ReplaceAllString(inc.ID, "_")
	desc := inc.Description
	if len(desc) > 200 {
		desc = desc[:200]
	}
	desc = strings.ReplaceAll(desc, `"`, `'`)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "rule %s {\n", ruleName)
	fmt.Fprintf(&buf, "    meta:\n")
	fmt.Fprintf(&buf, "        dragnet_id  = %q\n", inc.ID)
	fmt.Fprintf(&buf, "        severity    = %q\n", inc.Severity)
	fmt.Fprintf(&buf, "        description = %q\n", desc)
	fmt.Fprintf(&buf, "        source      = \"dragnet\"\n")
	if inc.CompromiseWindow.Start != "" {
		fmt.Fprintf(&buf, "        published   = %q\n", inc.CompromiseWindow.Start)
	}
	fmt.Fprintf(&buf, "    strings:\n")

	for i, h := range hashes {
		fmt.Fprintf(&buf, "        $hash_%d = %q ascii fullword nocase\n", i, h)
	}
	for i, d := range domains {
		fmt.Fprintf(&buf, "        $domain_%d = %q ascii wide nocase\n", i, d)
	}
	for i, ip := range ips {
		fmt.Fprintf(&buf, "        $ip_%d = %q ascii\n", i, ip)
	}
	for i, p := range paths {
		fmt.Fprintf(&buf, "        $path_%d = %q ascii wide\n", i, p)
	}

	fmt.Fprintf(&buf, "    condition:\n")
	fmt.Fprintf(&buf, "        %s\n", buildCondition(len(hashes), len(domains), len(ips), len(paths)))
	fmt.Fprintf(&buf, "}\n")

	return buf.Bytes(), nil
}

func ruleNameFromID(id string) string {
	return ruleNameSanitize.ReplaceAllString(id, "_")
}

func filterHashes(inc *incident.Incident) []string {
	var out []string
	for _, h := range inc.Indicators.FileHashes {
		if strings.EqualFold(h.Algorithm, "sha256") && h.Confidence >= minConfidence {
			out = append(out, h.Value)
		}
	}
	return out
}

func filterValues(vals []incident.IndicatorValue) []string {
	var out []string
	for _, v := range vals {
		if v.Confidence >= minConfidence {
			out = append(out, v.Value)
		}
	}
	return out
}

func filterPaths(inc *incident.Incident) []string {
	return inc.Indicators.FilePaths
}

func buildCondition(nhashes, ndomains, nips, npaths int) string {
	var parts []string
	if nhashes > 0 {
		parts = append(parts, "any of ($hash_*)")
	}
	if ndomains > 0 {
		parts = append(parts, "any of ($domain_*)")
	}
	if nips >= 2 {
		parts = append(parts, "2 of ($ip_*)")
	} else if nips == 1 {
		parts = append(parts, "any of ($ip_*)")
	}
	if npaths > 0 {
		parts = append(parts, "any of ($path_*)")
	}
	return strings.Join(parts, " or\n        ")
}
