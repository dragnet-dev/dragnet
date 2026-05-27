package osv

import "testing"

func TestOSVToIncidentNormalizesNamespacedEcosystem(t *testing.T) {
	adv := &osvAdvisory{
		ID:      "DRUPAL-CONTRIB-2025-041",
		Summary: "Drupal Colorbox advisory",
	}
	addAffected(adv, "drupal/colorbox", "Packagist:https://packages.drupal.org/8")

	inc := osvToIncident(adv)
	if inc == nil {
		t.Fatal("expected incident")
	}
	if inc.Source != "osv" {
		t.Fatalf("Source = %q, want osv", inc.Source)
	}
	if inc.ID != "packagist-osv-DRUPAL-CONTRIB-2025-041" {
		t.Fatalf("ID = %q", inc.ID)
	}
	if got := inc.Packages[0].Ecosystem; got != "packagist" {
		t.Fatalf("package ecosystem = %q, want packagist", got)
	}
	if got := inc.References[0]; got != "https://osv.dev/vulnerability/DRUPAL-CONTRIB-2025-041" {
		t.Fatalf("fallback reference = %q", got)
	}
}

func TestOSVToIncidentUsesFallbackDescriptionAndDatabaseSeverity(t *testing.T) {
	adv := &osvAdvisory{
		ID:      "PYSEC-2022-43165",
		Details: "A detailed advisory body from OSV.",
	}
	adv.DatabaseSpecific.Severity = "HIGH"
	addAffected(adv, "scoptrial", "PyPI")

	inc := osvToIncident(adv)
	if inc == nil {
		t.Fatal("expected incident")
	}
	if inc.Description != "A detailed advisory body from OSV." {
		t.Fatalf("Description = %q", inc.Description)
	}
	if inc.Severity != "high" {
		t.Fatalf("Severity = %q, want high", inc.Severity)
	}
}

func addAffected(adv *osvAdvisory, name, ecosystem string) {
	adv.Affected = append(adv.Affected, struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	}{})
	affected := &adv.Affected[len(adv.Affected)-1]
	affected.Package.Name = name
	affected.Package.Ecosystem = ecosystem
}
