package enrichment

import (
	"testing"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

func TestLinkOSToContainer_SharedCVE(t *testing.T) {
	containerInc := &incident.Incident{
		ID: "dragnet-container-2025-0001",
		CVEExt: &incident.CVEExtension{
			CVEID: "CVE-2025-1234",
		},
		ContainerExt: &incident.ContainerExtension{},
	}

	osInc := &incident.Incident{
		ID:       "dragnet-os-packages-2025-0001",
		Severity: "critical",
		OSVID:    "CVE-2025-1234",
		Packages: []incident.Package{
			{Name: "openssl", Ecosystem: "debian", AffectedVersions: []string{"3.0.1"}},
		},
		CVEExt: &incident.CVEExtension{CVEID: "CVE-2025-1234"},
	}

	LinkOSToContainer([]*incident.Incident{osInc}, []*incident.Incident{containerInc})

	if len(osInc.CrossDomainLinks) != 1 {
		t.Fatalf("expected 1 link on osInc, got %d", len(osInc.CrossDomainLinks))
	}
	if osInc.CrossDomainLinks[0].Module != "container" {
		t.Errorf("expected link to container module, got %q", osInc.CrossDomainLinks[0].Module)
	}
	if osInc.CrossDomainLinks[0].IncidentID != containerInc.ID {
		t.Errorf("expected link to %q, got %q", containerInc.ID, osInc.CrossDomainLinks[0].IncidentID)
	}

	if len(containerInc.CrossDomainLinks) != 1 {
		t.Fatalf("expected 1 back-link on containerInc, got %d", len(containerInc.CrossDomainLinks))
	}
	if containerInc.CrossDomainLinks[0].Module != "os-packages" {
		t.Errorf("expected back-link to os-packages, got %q", containerInc.CrossDomainLinks[0].Module)
	}

	// Package-version IOC should be added to container incident
	if len(containerInc.Indicators.URLs) == 0 {
		t.Error("expected package-version IOC added to container incident URLs")
	}
	if containerInc.Indicators.URLs[0].Value != "openssl/3.0.1" {
		t.Errorf("expected IOC value 'openssl/3.0.1', got %q", containerInc.Indicators.URLs[0].Value)
	}
}

func TestLinkOSToContainer_NoMatch(t *testing.T) {
	containerInc := &incident.Incident{
		ID:           "dragnet-container-2025-0001",
		CVEExt:       &incident.CVEExtension{CVEID: "CVE-2025-9999"},
		ContainerExt: &incident.ContainerExtension{},
	}
	osInc := &incident.Incident{
		ID:     "dragnet-os-packages-2025-0001",
		OSVID:  "CVE-2025-1234",
		CVEExt: &incident.CVEExtension{CVEID: "CVE-2025-1234"},
	}

	LinkOSToContainer([]*incident.Incident{osInc}, []*incident.Incident{containerInc})

	if len(osInc.CrossDomainLinks) != 0 {
		t.Errorf("expected no links on non-matching CVE IDs, got %d", len(osInc.CrossDomainLinks))
	}
}

func TestLinkOSToContainer_IdempotentLinks(t *testing.T) {
	containerInc := &incident.Incident{
		ID:           "dragnet-container-2025-0001",
		CVEExt:       &incident.CVEExtension{CVEID: "CVE-2025-1234"},
		ContainerExt: &incident.ContainerExtension{},
	}
	osInc := &incident.Incident{
		ID:     "dragnet-os-packages-2025-0001",
		OSVID:  "CVE-2025-1234",
		CVEExt: &incident.CVEExtension{CVEID: "CVE-2025-1234"},
	}

	// Call twice — links should not be duplicated.
	LinkOSToContainer([]*incident.Incident{osInc}, []*incident.Incident{containerInc})
	LinkOSToContainer([]*incident.Incident{osInc}, []*incident.Incident{containerInc})

	if len(osInc.CrossDomainLinks) != 1 {
		t.Errorf("expected 1 link after idempotent call, got %d", len(osInc.CrossDomainLinks))
	}
}
