package incident

import (
	"testing"
)

func TestMergeSingleIncident(t *testing.T) {
	inc := &Incident{ID: "npm-2026-001", Severity: "critical"}
	got, err := Merge([]*Incident{inc})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "npm-2026-001" {
		t.Errorf("got ID %q, want npm-2026-001", got.ID)
	}
}

func TestMergeEmpty(t *testing.T) {
	got, err := Merge(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("expected nil for empty input, got %+v", got)
	}
}

func TestMergeByPackageOverlap(t *testing.T) {
	a := &Incident{
		ID:         "npm-2026-001",
		Severity:   "high",
		Packages:   []Package{{Name: "@tanstack/react-router", Ecosystem: "npm"}},
		References: []string{"https://wiz.io/blog/tanstack"},
		Indicators: Indicators{
			Domains: []IndicatorValue{{Value: "git-tanstack.com", Sources: []string{"wiz"}, Confidence: 0.90}},
		},
	}
	b := &Incident{
		ID:         "npm-2026-001b",
		Severity:   "critical",
		Packages:   []Package{{Name: "@tanstack/react-router", Ecosystem: "npm"}},
		References: []string{"https://socket.dev/blog/tanstack"},
		Indicators: Indicators{
			Domains: []IndicatorValue{{Value: "git-tanstack.com", Sources: []string{"socket"}, Confidence: 0.90}},
			IPs:     []IndicatorValue{{Value: "83.142.209.194", Sources: []string{"socket"}, Confidence: 0.90}},
		},
	}

	got, err := Merge([]*Incident{a, b})
	if err != nil {
		t.Fatal(err)
	}

	// Severity should be highest
	if got.Severity != "critical" {
		t.Errorf("severity = %q, want critical", got.Severity)
	}

	// References should be unioned
	if len(got.References) != 2 {
		t.Errorf("references len = %d, want 2", len(got.References))
	}

	// Domain should be merged with both sources
	if len(got.Indicators.Domains) != 1 {
		t.Errorf("domains len = %d, want 1", len(got.Indicators.Domains))
	}
	if len(got.Indicators.Domains[0].Sources) != 2 {
		t.Errorf("domain sources len = %d, want 2", len(got.Indicators.Domains[0].Sources))
	}

	// IP should be present
	if len(got.Indicators.IPs) != 1 {
		t.Errorf("ips len = %d, want 1", len(got.Indicators.IPs))
	}
}

func TestMergeNoCrossGroup(t *testing.T) {
	// Two incidents with different packages and no IOC overlap should NOT merge
	a := &Incident{
		ID:       "npm-2026-001",
		Packages: []Package{{Name: "pkg-a", Ecosystem: "npm"}},
	}
	b := &Incident{
		ID:       "npm-2026-002",
		Packages: []Package{{Name: "pkg-b", Ecosystem: "npm"}},
	}

	all := MergeAll([]*Incident{a, b})
	if len(all) != 2 {
		t.Errorf("expected 2 independent incidents, got %d", len(all))
	}
}

// TestMergeTransitivity verifies that A↔B and B↔C ⟹ {A,B,C} in one group,
// even when A and C share no direct merge criteria.
func TestMergeTransitivity(t *testing.T) {
	campaign := "Operation Sandstorm"
	// A and B share a campaign name → should merge.
	a := &Incident{
		ID:       "npm-2026-001",
		Campaign: Campaign{Name: campaign},
		Packages: []Package{{Name: "pkg-a", Ecosystem: "npm"}},
	}
	// B and C share a package → should merge. A and C share nothing directly.
	b := &Incident{
		ID:       "npm-2026-002",
		Campaign: Campaign{Name: campaign},
		Packages: []Package{{Name: "pkg-b", Ecosystem: "npm"}},
	}
	c := &Incident{
		ID:       "npm-2026-003",
		Packages: []Package{{Name: "pkg-b", Ecosystem: "npm"}},
	}

	all := MergeAll([]*Incident{a, b, c})
	if len(all) != 1 {
		t.Errorf("expected 1 merged incident (transitive: A↔B↔C), got %d", len(all))
	}
}

func TestMergeAllByCampaign(t *testing.T) {
	a := &Incident{
		ID:       "npm-2026-001",
		Campaign: Campaign{Name: "Mini Shai-Hulud"},
		Packages: []Package{{Name: "pkg-a", Ecosystem: "npm"}},
		Severity: "high",
	}
	b := &Incident{
		ID:       "pypi-2026-001",
		Campaign: Campaign{Name: "Mini Shai-Hulud"},
		Packages: []Package{{Name: "pkg-b", Ecosystem: "pypi"}},
		Severity: "critical",
	}

	all := MergeAll([]*Incident{a, b})
	if len(all) != 1 {
		t.Errorf("expected 1 merged incident (campaign match), got %d", len(all))
	}
	if all[0].Severity != "critical" {
		t.Errorf("merged severity = %q, want critical", all[0].Severity)
	}
}
