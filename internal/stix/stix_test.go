package stix

import (
	"strings"
	"testing"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

func TestStixIDDeterminism(t *testing.T) {
	a := StixID("indicator", "npm-2026-001:test")
	b := StixID("indicator", "npm-2026-001:test")
	if a != b {
		t.Fatalf("non-deterministic: %s != %s", a, b)
	}
	if !strings.HasPrefix(a, "indicator--") {
		t.Fatalf("wrong prefix: %s", a)
	}
}

func TestStixIDUniqueness(t *testing.T) {
	a := StixID("indicator", "seed-a")
	b := StixID("indicator", "seed-b")
	if a == b {
		t.Fatal("different seeds produced the same ID")
	}
	c := StixID("malware", "seed-a")
	if a == c {
		t.Fatal("different types with same seed produced the same ID")
	}
}

func TestPatterns(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{DomainPattern("evil.com"), "[domain-name:value = 'evil.com']"},
		{IPv4Pattern("1.2.3.4"), "[ipv4-addr:value = '1.2.3.4']"},
		{URLPattern("http://x.com"), "[url:value = 'http://x.com']"},
		{SHA256Pattern("abc"), "[file:hashes.SHA256 = 'abc']"},
		{SHA1Pattern("abc"), "[file:hashes.SHA1 = 'abc']"},
		{MD5Pattern("abc"), "[file:hashes.MD5 = 'abc']"},
		{FileNamePattern("evil.exe"), "[file:name = 'evil.exe']"},
		{ServicePattern("svc"), "[process:name = 'svc']"},
		{FilePathPattern("/etc/evil.sh"), "[file:name = '/etc/evil.sh']"},
		{FilePathPattern("~/Library/LaunchAgents/com.evil.plist"), "[file:name = '~/Library/LaunchAgents/com.evil.plist']"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

func TestGenerateBundleMinimal(t *testing.T) {
	inc := &incident.Incident{
		ID:          "test-2026-001",
		AttackType:  "malicious_publish",
		Description: "test incident",
		Indicators: incident.Indicators{
			Domains: []incident.IndicatorValue{
				{Value: "evil.com", Confidence: 0.90},
			},
		},
	}

	bundle := GenerateBundle(inc)

	if bundle.Type != "bundle" {
		t.Fatalf("wrong bundle type: %s", bundle.Type)
	}
	if !strings.HasPrefix(bundle.ID, "bundle--") {
		t.Fatalf("wrong bundle ID format: %s", bundle.ID)
	}

	typeCount := map[string]int{}
	for _, obj := range bundle.Objects {
		switch v := obj.(type) {
		case Identity:
			typeCount[v.Type]++
		case Indicator:
			typeCount[v.Type]++
		case Campaign:
			typeCount[v.Type]++
		case AttackPattern:
			typeCount[v.Type]++
		case Relationship:
			typeCount[v.Type]++
		}
	}

	if typeCount["identity"] != 1 {
		t.Errorf("expected 1 identity, got %d", typeCount["identity"])
	}
	if typeCount["indicator"] != 1 {
		t.Errorf("expected 1 indicator, got %d", typeCount["indicator"])
	}
}

func TestBuildCombinedBundle(t *testing.T) {
	inc1 := &incident.Incident{
		ID:         "test-2026-001",
		AttackType: "malicious_publish",
		Indicators: incident.Indicators{
			Domains: []incident.IndicatorValue{{Value: "a.com", Confidence: 0.8}},
		},
	}
	inc2 := &incident.Incident{
		ID:         "test-2026-002",
		AttackType: "malicious_publish",
		Indicators: incident.Indicators{
			Domains: []incident.IndicatorValue{{Value: "b.com", Confidence: 0.8}},
		},
	}

	b1 := GenerateBundle(inc1)
	b2 := GenerateBundle(inc2)
	combined := BuildCombinedBundle([]Bundle{b1, b2})

	// Identity should appear only once despite being in both bundles
	identityCount := 0
	for _, obj := range combined.Objects {
		if id, ok := obj.(Identity); ok && id.Type == "identity" {
			identityCount++
		}
	}
	if identityCount != 1 {
		t.Errorf("expected 1 deduplicated identity, got %d", identityCount)
	}

	if len(combined.Objects) < 3 {
		t.Errorf("expected at least 3 objects in combined bundle, got %d", len(combined.Objects))
	}
}

func TestValidatePasses(t *testing.T) {
	inc := &incident.Incident{
		ID:          "test-2026-001",
		AttackType:  "account_takeover",
		Description: "test",
		References:  []string{"https://example.com"},
		Indicators: incident.Indicators{
			Domains: []incident.IndicatorValue{{Value: "evil.com", Confidence: 0.90}},
			IPs:     []incident.IndicatorValue{{Value: "1.2.3.4", Confidence: 0.85}},
			FileHashes: []incident.FileHash{
				{Algorithm: "sha256", Value: "abc123", Confidence: 0.95},
			},
			Persistence: &incident.Persistence{
				ServiceNames:     []string{"evild"},
				MacOSLaunchAgent: []string{"~/Library/LaunchAgents/com.evil.plist"},
				LinuxSystemd:     []string{"~/.config/systemd/user/evil.service"},
			},
			FilePaths: []string{"/tmp/evil.sh"},
		},
		Campaign: incident.Campaign{Name: "EvilCampaign", Actor: "EvilGroup", Confidence: "high"},
		Hunting: incident.Hunting{
			MITRETechniques: []incident.MITRETechnique{
				{ID: "T1195.002", Name: "Supply Chain Compromise"},
			},
		},
	}

	bundle := GenerateBundle(inc)
	errs := Validate(bundle)
	if len(errs) > 0 {
		for _, e := range errs {
			t.Errorf("unexpected validation error: %s", e)
		}
	}
}

func TestValidateDetectsEmptyPattern(t *testing.T) {
	bundle := Bundle{
		Type: "bundle",
		ID:   StixID("bundle", "test"),
		Objects: []any{
			Indicator{
				Common: Common{
					Type:        "indicator",
					ID:          StixID("indicator", "test"),
					SpecVersion: "2.1",
					Created:     mustTime(),
					Modified:    mustTime(),
				},
				// Pattern intentionally missing
				PatternType:    "stix",
				PatternVersion: "2.1",
				ValidFrom:      mustTime(),
				IndicatorTypes: []string{"malicious-activity"},
			},
		},
	}

	errs := Validate(bundle)
	found := false
	for _, e := range errs {
		if e.Field == "pattern" {
			found = true
		}
	}
	if !found {
		t.Error("expected validation error for missing pattern, got none")
	}
}

func TestValidateDetectsDanglingRef(t *testing.T) {
	srcID := StixID("indicator", "dangling-test")
	bundle := Bundle{
		Type: "bundle",
		ID:   StixID("bundle", "test"),
		Objects: []any{
			Relationship{
				Common: Common{
					Type:        "relationship",
					ID:          StixID("relationship", "dangling"),
					SpecVersion: "2.1",
					Created:     mustTime(),
					Modified:    mustTime(),
				},
				RelationshipType: "indicates",
				SourceRef:        srcID,
				TargetRef:        "campaign--00000000-0000-0000-0000-000000000000", // not in bundle
			},
		},
	}

	errs := Validate(bundle)
	found := false
	for _, e := range errs {
		if e.Field == "target_ref" {
			found = true
		}
	}
	if !found {
		t.Error("expected validation error for dangling target_ref, got none")
	}
}

func TestValidateDetectsBadIDFormat(t *testing.T) {
	bundle := Bundle{
		Type: "bundle",
		ID:   StixID("bundle", "test"),
		Objects: []any{
			Identity{
				Common: Common{
					Type:        "identity",
					ID:          "identity--not-a-uuid",
					SpecVersion: "2.1",
					Created:     mustTime(),
					Modified:    mustTime(),
				},
				Name:          "test",
				IdentityClass: "system",
			},
		},
	}

	errs := Validate(bundle)
	found := false
	for _, e := range errs {
		if e.Field == "id" {
			found = true
		}
	}
	if !found {
		t.Error("expected validation error for malformed ID, got none")
	}
}

func TestValidatePersistenceIndicators(t *testing.T) {
	inc := &incident.Incident{
		ID:         "test-2026-persist",
		AttackType: "malicious_publish",
		Indicators: incident.Indicators{
			Persistence: &incident.Persistence{
				MacOSLaunchAgent: []string{"~/Library/LaunchAgents/com.evil.plist"},
				LinuxSystemd:     []string{"~/.config/systemd/user/evil.service"},
			},
			FilePaths: []string{"/tmp/backdoor.sh"},
		},
	}

	bundle := GenerateBundle(inc)

	// Count file indicators
	fileIndicators := 0
	for _, obj := range bundle.Objects {
		if ind, ok := obj.(Indicator); ok {
			if strings.Contains(ind.Pattern, "file:name") {
				fileIndicators++
			}
		}
	}
	if fileIndicators != 3 { // LaunchAgent + systemd + file_path
		t.Errorf("expected 3 file indicators (LaunchAgent + systemd + file_path), got %d", fileIndicators)
	}

	errs := Validate(bundle)
	if len(errs) > 0 {
		for _, e := range errs {
			t.Errorf("unexpected validation error: %s", e)
		}
	}
}

func mustTime() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}
