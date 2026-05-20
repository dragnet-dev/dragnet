package osv

import (
	"testing"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

func incWithSeverity(sev string, pkgs []incident.Package) *incident.Incident {
	return &incident.Incident{
		ID:       "test-" + sev,
		Severity: sev,
		Packages: pkgs,
	}
}

func TestOSFilterSeverityGate(t *testing.T) {
	f := NewOSFilter(nil, false)

	if f.Pass(incWithSeverity("low", nil)) {
		t.Error("low severity should not pass")
	}
	if f.Pass(incWithSeverity("medium", nil)) {
		t.Error("medium severity should not pass")
	}
	if !f.Pass(incWithSeverity("high", nil)) {
		t.Error("high severity should pass")
	}
	if !f.Pass(incWithSeverity("critical", nil)) {
		t.Error("critical severity should pass")
	}
}

func TestOSFilterRequireFixOrKEV(t *testing.T) {
	f := NewOSFilter(nil, true)

	// high severity but no fix and not KEV → filtered
	if f.Pass(incWithSeverity("high", []incident.Package{{Name: "openssl", Ecosystem: "debian"}})) {
		t.Error("high with no fix and no KEV should not pass when RequireFixOrKEV=true")
	}

	// has fix version → passes
	inc := incWithSeverity("high", []incident.Package{
		{Name: "openssl", Ecosystem: "debian", AffectedVersions: []string{"3.0.1"}},
	})
	if !f.Pass(inc) {
		t.Error("high with fix version should pass")
	}

	// KEV-listed (no fix needed) → passes
	inc2 := incWithSeverity("critical", []incident.Package{{Name: "curl", Ecosystem: "alpine"}})
	inc2.CVEExt = &incident.CVEExtension{ExploitedInWild: true}
	if !f.Pass(inc2) {
		t.Error("critical KEV-listed with no fix should pass")
	}
}

func TestOSFilterImagePresenceGate(t *testing.T) {
	imgPkgs := map[string]bool{"openssl": true, "curl": true}
	f := NewOSFilter(imgPkgs, false)

	// Package not in images → filtered
	if f.Pass(incWithSeverity("high", []incident.Package{{Name: "obscure-lib", Ecosystem: "debian"}})) {
		t.Error("package not in image set should not pass image gate")
	}

	// Package in images → passes
	if !f.Pass(incWithSeverity("high", []incident.Package{{Name: "openssl", Ecosystem: "debian"}})) {
		t.Error("package in image set should pass image gate")
	}

	// nil image set = gate disabled → passes regardless
	f2 := NewOSFilter(nil, false)
	if !f2.Pass(incWithSeverity("high", []incident.Package{{Name: "obscure-lib", Ecosystem: "debian"}})) {
		t.Error("nil image set should skip image gate")
	}
}

func TestOSFilterAll(t *testing.T) {
	f := NewOSFilter(nil, true)
	incidents := []*incident.Incident{
		incWithSeverity("low", nil),
		incWithSeverity("medium", nil),
		{ID: "pass", Severity: "high", Packages: []incident.Package{
			{Name: "curl", Ecosystem: "alpine", AffectedVersions: []string{"7.88"}},
		}},
		{ID: "pass2", Severity: "critical", CVEExt: &incident.CVEExtension{ExploitedInWild: true}},
	}
	out := f.FilterAll(incidents)
	if len(out) != 2 {
		t.Errorf("expected 2 passing incidents, got %d", len(out))
	}
}
