package yara

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

func TestGenerateFromIncident_Golden(t *testing.T) {
	raw, err := os.ReadFile("testdata/input_malware.json")
	if err != nil {
		t.Fatal(err)
	}
	var inc incident.Incident
	if err := json.Unmarshal(raw, &inc); err != nil {
		t.Fatal(err)
	}

	b := New()
	got, err := b.GenerateFromIncident(&inc)
	if err != nil {
		t.Fatal(err)
	}

	want, err := os.ReadFile("testdata/golden_malware.yar")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("golden mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestGenerateFromIncident_AllLowConfidence_NoSourceRule(t *testing.T) {
	inc := &incident.Incident{
		ID:       "dragnet-malware-2024-0002",
		Severity: "high",
		Indicators: incident.Indicators{
			Domains: []incident.IndicatorValue{
				{Value: "c2.example.com", Confidence: 0.3},
			},
			FileHashes: []incident.FileHash{
				{Algorithm: "sha256", Value: "aabb", Confidence: 0.5},
			},
		},
	}
	b := New()
	got, err := b.GenerateFromIncident(inc)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("expected nil output for all-low-confidence incident with no source rule, got:\n%s", got)
	}
}

func TestGenerateFromIncident_SourceRulePassthrough(t *testing.T) {
	sourceRule := "rule MalwareBazaar_RedLine {\n    condition: true\n}\n"
	inc := &incident.Incident{
		ID:       "dragnet-malware-2024-0005",
		Severity: "critical",
		MalwareExt: &incident.MalwareExtension{
			YaraRules: []incident.YaraRule{
				{Name: "MalwareBazaar_RedLine", Body: sourceRule, Confidence: 0.95},
				{Name: "NameOnly_NoBody", SourceURL: "https://example.com/rule"},
			},
		},
		// Low-confidence indicators — no IOC rule generated
		Indicators: incident.Indicators{
			Domains: []incident.IndicatorValue{
				{Value: "c2.example.com", Confidence: 0.1},
			},
		},
	}
	b := New()
	got, err := b.GenerateFromIncident(inc)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected non-nil output when source rule body is present")
	}
	out := string(got)
	if !contains(out, "MalwareBazaar_RedLine") {
		t.Error("source rule body should appear in output")
	}
	// No IOC rule since indicators are low confidence
	if contains(out, "dragnet_ioc_") {
		t.Error("IOC rule should not appear when no indicators pass confidence gate")
	}
}

func TestGenerateFromIncident_CombineSourceAndIOC(t *testing.T) {
	sourceRule := "rule SourceProvided {\n    condition: true\n}\n"
	inc := &incident.Incident{
		ID:       "dragnet-malware-2024-0006",
		Severity: "high",
		MalwareExt: &incident.MalwareExtension{
			YaraRules: []incident.YaraRule{
				{Name: "SourceProvided", Body: sourceRule, Confidence: 0.9},
			},
		},
		Indicators: incident.Indicators{
			Domains: []incident.IndicatorValue{
				{Value: "c2.example.com", Confidence: 0.9},
			},
		},
	}
	b := New()
	got, err := b.GenerateFromIncident(inc)
	if err != nil {
		t.Fatal(err)
	}
	out := string(got)
	if !contains(out, "SourceProvided") {
		t.Error("source rule body should appear in output")
	}
	if !contains(out, "dragnet_ioc_") {
		t.Error("IOC rule should also appear when indicators pass confidence gate")
	}
}

func TestGenerateFromIncident_MixedConfidence(t *testing.T) {
	inc := &incident.Incident{
		ID:       "dragnet-malware-2024-0003",
		Severity: "critical",
		Indicators: incident.Indicators{
			Domains: []incident.IndicatorValue{
				{Value: "good.example.com", Confidence: 0.9},
				{Value: "bad.example.com", Confidence: 0.2},
			},
			FileHashes: []incident.FileHash{
				{Algorithm: "sha256", Value: "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111", Confidence: 0.8},
				{Algorithm: "md5", Value: "deadbeef", Confidence: 0.9},
				{Algorithm: "sha256", Value: "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222", Confidence: 0.1},
			},
		},
	}
	b := New()
	got, err := b.GenerateFromIncident(inc)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected non-nil output")
	}
	out := string(got)
	if !contains(out, "aaaa1111") {
		t.Error("expected high-confidence sha256 in output")
	}
	if contains(out, "deadbeef") {
		t.Error("md5 hash should not appear in output")
	}
	if contains(out, "bbbb2222") {
		t.Error("low-confidence sha256 should not appear in output")
	}
	if !contains(out, "good.example.com") {
		t.Error("expected high-confidence domain in output")
	}
	if contains(out, "bad.example.com") {
		t.Error("low-confidence domain should not appear in output")
	}
}

func TestGenerateFromIncident_IPOnly_TwoRequired(t *testing.T) {
	inc := &incident.Incident{
		ID:       "dragnet-malware-2024-0004",
		Severity: "medium",
		Indicators: incident.Indicators{
			IPs: []incident.IndicatorValue{
				{Value: "10.0.0.1", Confidence: 0.9},
				{Value: "10.0.0.2", Confidence: 0.8},
			},
		},
	}
	b := New()
	got, err := b.GenerateFromIncident(inc)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected non-nil output for two-IP incident")
	}
	if !contains(string(got), "2 of ($ip_*)") {
		t.Error("expected '2 of ($ip_*)' condition for two-IP incident")
	}
}

func TestGenerateFromIncident_RuleNamePrefix(t *testing.T) {
	inc := &incident.Incident{
		ID:       "dragnet-malware-2024-0099",
		Severity: "high",
		Indicators: incident.Indicators{
			Domains: []incident.IndicatorValue{
				{Value: "c2.example.com", Confidence: 0.9},
			},
		},
	}
	b := New()
	got, err := b.GenerateFromIncident(inc)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(got), "rule dragnet_ioc_dragnet_malware_2024_0099") {
		t.Errorf("expected ioc-prefixed rule name, got:\n%s", got)
	}
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
