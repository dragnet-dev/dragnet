package sigma

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/deconflict"
	"github.com/dragnet-dev/dragnet/internal/incident"
)

// minimalIncident returns an incident with at least one IOC in every layer.
func minimalIncident() *incident.Incident {
	return &incident.Incident{
		ID:          "DRAG-TEST-001",
		Severity:    "high",
		Description: "Test incident for sigma generator.",
		References:  []string{"https://example.com/advisory-1"},
		Packages: []incident.Package{
			{Name: "evil-pkg", Ecosystem: "npm"},
		},
		Campaign:         incident.Campaign{Confidence: "high"},
		CompromiseWindow: incident.CompromiseWindow{Start: "2026-05-01T00:00:00Z"},
		Exposure: incident.Exposure{
			LockfileSignatures: []string{"evil-pkg@1.2.3"},
			FilePresence:       []string{"router_init.js"},
		},
		Indicators: incident.Indicators{
			Domains: []incident.IndicatorValue{
				{Value: "c2.evil.example.com", Confidence: 0.90},
			},
			IPs: []incident.IndicatorValue{
				{Value: "192.0.2.1", Confidence: 0.80},
			},
			FileHashes: []incident.FileHash{
				{Algorithm: "sha256", Value: "abc123def456", Filename: "evil.js", Confidence: 0.95},
			},
			Persistence: &incident.Persistence{
				ServiceNames:     []string{"evil-svc"},
				MacOSLaunchAgent: []string{"com.evil.plist"},
				LinuxSystemd:     []string{"evil.service"},
			},
			SessionNetwork: &incident.SessionNetwork{
				RecipientID: "05abc123",
				SeedNodes:   []string{"seed1.getsession.org"},
				FileServer:  "files.evil.example.com",
			},
		},
		Hunting: incident.Hunting{
			MITRETechniques: []incident.MITRETechnique{
				{ID: "T1195.002", Name: "Supply Chain Compromise"},
			},
			Behaviours: []incident.Behaviour{
				{ID: "BEH-001", Description: "reads /proc/*/mem", Platform: "linux"},
				{ID: "BEH-002", Description: "unexpected outbound connection", Platform: "any"},
				{ID: "BEH-003", Description: "creates LaunchAgent", Platform: "macos"},
				{ID: "BEH-006", Description: "executes rm -rf", Platform: "linux"},
			},
		},
	}
}

func TestGenerate_CreatesExpectedFiles(t *testing.T) {
	outDir := t.TempDir()
	gen := New(outDir, "test", nil)

	inc := minimalIncident()
	if err := gen.Generate(inc); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	expectedFiles := []string{
		filepath.Join(outDir, "exposure", "2026", "DRAG-TEST-001-exposure.yaml"),
		filepath.Join(outDir, "exposure", "2026", "DRAG-TEST-001-exposure-file-presence.yaml"),
		filepath.Join(outDir, "ioc", "2026", "DRAG-TEST-001-ioc-network.yaml"),
		filepath.Join(outDir, "ioc", "2026", "DRAG-TEST-001-ioc-hashes.yaml"),
		filepath.Join(outDir, "ioc", "2026", "DRAG-TEST-001-ioc-persistence.yaml"),
		filepath.Join(outDir, "ioc", "2026", "DRAG-TEST-001-ioc-session.yaml"),
		filepath.Join(outDir, "hunting", "2026", "DRAG-TEST-001-hunting-BEH-001.yaml"),
		filepath.Join(outDir, "hunting", "2026", "DRAG-TEST-001-hunting-BEH-002.yaml"),
		filepath.Join(outDir, "hunting", "2026", "DRAG-TEST-001-hunting-BEH-003.yaml"),
		filepath.Join(outDir, "hunting", "2026", "DRAG-TEST-001-hunting-BEH-006.yaml"),
	}

	for _, path := range expectedFiles {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected file not found: %s", path)
		}
	}
}

func TestGenerate_LockfileContent(t *testing.T) {
	outDir := t.TempDir()
	gen := New(outDir, "test", nil)

	inc := minimalIncident()
	if err := gen.Generate(inc); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "exposure", "2026", "DRAG-TEST-001-exposure.yaml"))
	if err != nil {
		t.Fatalf("reading exposure rule: %v", err)
	}
	content := string(data)

	checks := []struct {
		desc string
		want string
	}{
		{"incident ID in title", "DRAG-TEST-001"},
		{"lockfile signature", "evil-pkg@1.2.3"},
		{"level high", "level: high"},
		{"logsource category", "category: file_event"},
		{"reference", "https://example.com/advisory-1"},
		{"MITRE tag", "attack.t1195002"},
		{"status stable (confidence 0.90)", "status: stable"},
	}

	for _, c := range checks {
		if !strings.Contains(content, c.want) {
			t.Errorf("lockfile rule missing %s: want %q\n---\n%s", c.desc, c.want, content)
		}
	}
}

func TestGenerate_NetworkIOCContent(t *testing.T) {
	outDir := t.TempDir()
	gen := New(outDir, "test", nil)

	inc := minimalIncident()
	if err := gen.Generate(inc); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "ioc", "2026", "DRAG-TEST-001-ioc-network.yaml"))
	if err != nil {
		t.Fatalf("reading network IOC rule: %v", err)
	}
	content := string(data)

	checks := []struct {
		desc string
		want string
	}{
		{"C2 domain", "c2.evil.example.com"},
		{"C2 IP", "192.0.2.1"},
		{"network condition", "selection_domain or selection_ip"},
		{"logsource category", "category: network_connection"},
	}

	for _, c := range checks {
		if !strings.Contains(content, c.want) {
			t.Errorf("network IOC rule missing %s: want %q\n---\n%s", c.desc, c.want, content)
		}
	}
}

func TestGenerate_FileHashContent(t *testing.T) {
	outDir := t.TempDir()
	gen := New(outDir, "test", nil)

	inc := minimalIncident()
	if err := gen.Generate(inc); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "ioc", "2026", "DRAG-TEST-001-ioc-hashes.yaml"))
	if err != nil {
		t.Fatalf("reading file hash rule: %v", err)
	}
	content := string(data)

	// Algorithm should be uppercased by the `upper` func
	if !strings.Contains(content, "SHA256=abc123def456") {
		t.Errorf("file hash rule missing uppercased hash: want SHA256=abc123def456\n---\n%s", content)
	}
}

func TestGenerate_PersistenceContent(t *testing.T) {
	outDir := t.TempDir()
	gen := New(outDir, "test", nil)

	inc := minimalIncident()
	if err := gen.Generate(inc); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "ioc", "2026", "DRAG-TEST-001-ioc-persistence.yaml"))
	if err != nil {
		t.Fatalf("reading persistence rule: %v", err)
	}
	content := string(data)

	for _, want := range []string{"evil-svc", "com.evil.plist", "evil.service"} {
		if !strings.Contains(content, want) {
			t.Errorf("persistence rule missing %q\n---\n%s", want, content)
		}
	}
}

func TestGenerate_SessionNetworkContent(t *testing.T) {
	outDir := t.TempDir()
	gen := New(outDir, "test", nil)

	inc := minimalIncident()
	if err := gen.Generate(inc); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "ioc", "2026", "DRAG-TEST-001-ioc-session.yaml"))
	if err != nil {
		t.Fatalf("reading session network rule: %v", err)
	}
	content := string(data)

	for _, want := range []string{"05abc123", "seed1.getsession.org", "files.evil.example.com"} {
		if !strings.Contains(content, want) {
			t.Errorf("session network rule missing %q\n---\n%s", want, content)
		}
	}
}

func TestGenerate_HuntingBEH001(t *testing.T) {
	outDir := t.TempDir()
	gen := New(outDir, "test", nil)

	inc := minimalIncident()
	if err := gen.Generate(inc); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "hunting", "2026", "DRAG-TEST-001-hunting-BEH-001.yaml"))
	if err != nil {
		t.Fatalf("reading BEH-001 hunting rule: %v", err)
	}
	content := string(data)

	checks := []string{
		"BEH-001",
		"/proc/",
		"/mem",
		"process_access",
		"linux",
	}
	for _, want := range checks {
		if !strings.Contains(content, want) {
			t.Errorf("BEH-001 rule missing %q\n---\n%s", want, content)
		}
	}
}

func TestGenerate_SkipsEmptyLayers(t *testing.T) {
	outDir := t.TempDir()
	gen := New(outDir, "test", nil)

	// Incident with no IOC network indicators, no session, no persistence
	inc := &incident.Incident{
		ID:          "DRAG-MINIMAL-001",
		Severity:    "low",
		Description: "Minimal incident.",
		References:  []string{},
		Packages:    []incident.Package{{Name: "tiny-pkg", Ecosystem: "pypi"}},
		Exposure: incident.Exposure{
			LockfileSignatures: []string{"tiny-pkg==0.0.1"},
		},
	}

	if err := gen.Generate(inc); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// These files must NOT exist because there are no indicators
	absent := []string{
		filepath.Join(outDir, "ioc", "2026", "DRAG-MINIMAL-001-ioc-network.yaml"),
		filepath.Join(outDir, "ioc", "2026", "DRAG-MINIMAL-001-ioc-hashes.yaml"),
		filepath.Join(outDir, "ioc", "2026", "DRAG-MINIMAL-001-ioc-persistence.yaml"),
		filepath.Join(outDir, "ioc", "2026", "DRAG-MINIMAL-001-ioc-session.yaml"),
	}
	for _, path := range absent {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("expected file to NOT exist but it does: %s", path)
		}
	}

	// This file must exist
	present := filepath.Join(outDir, "exposure", "2026", "DRAG-MINIMAL-001-exposure.yaml")
	if _, err := os.Stat(present); os.IsNotExist(err) {
		t.Errorf("expected exposure lockfile rule to exist: %s", present)
	}
}

func TestRuleID_Deterministic(t *testing.T) {
	id1 := RuleID("DRAG-001", "ioc", "network")
	id2 := RuleID("DRAG-001", "ioc", "network")
	id3 := RuleID("DRAG-001", "ioc", "hashes")

	if id1 != id2 {
		t.Errorf("RuleID not deterministic: %v != %v", id1, id2)
	}
	if id1 == id3 {
		t.Errorf("different subtypes produced same UUID: %v", id1)
	}
}

func TestDeconflictIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.0.0.100",         // loopback
		"169.254.169.254", "169.254.170.2", // link-local / cloud IMDS
		"10.0.0.1", "10.255.255.255",       // RFC1918
		"172.16.0.1", "172.31.255.255",     // RFC1918
		"192.168.1.1", "192.168.0.0",       // RFC1918
		"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", // public DNS
	}
	allowed := []string{
		"142.11.206.73", "94.154.172.43", "37.16.75.69", // real C2 IPs
		"52.14.0.1", "104.26.10.75",                     // public cloud
	}
	for _, ip := range blocked {
		if !deconflict.IP(ip) {
			t.Errorf("deconflict.IP(%q) = false, want true", ip)
		}
	}
	for _, ip := range allowed {
		if deconflict.IP(ip) {
			t.Errorf("deconflict.IP(%q) = true, want false", ip)
		}
	}
}

func TestTruncateReferences(t *testing.T) {
	// Under limit — unchanged
	few := []string{"https://nvd.nist.gov/a", "https://example.com/b"}
	if got := truncateReferences(few); len(got) != 2 {
		t.Errorf("short list: len=%d, want 2", len(got))
	}

	// Build 20 GHSA links + 1 NVD + 1 named blog — should cap at maxReferences
	// with high-priority refs retained.
	refs := make([]string, 20)
	for i := range refs {
		refs[i] = fmt.Sprintf("https://github.com/advisories/GHSA-%04d", i)
	}
	refs = append(refs, "https://nvd.nist.gov/vuln/detail/CVE-2026-1234")
	refs = append(refs, "https://aikido.dev/blog/some-post")

	got := truncateReferences(refs)
	if len(got) != maxReferences {
		t.Errorf("len=%d, want %d", len(got), maxReferences)
	}
	var hasNVD, hasAikido bool
	for _, r := range got {
		if strings.Contains(r, "nvd.nist.gov") {
			hasNVD = true
		}
		if strings.Contains(r, "aikido.dev") {
			hasAikido = true
		}
	}
	if !hasNVD {
		t.Error("NVD link missing from truncated references")
	}
	if !hasAikido {
		t.Error("aikido.dev link missing from truncated references")
	}
}
