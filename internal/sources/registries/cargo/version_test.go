package cargo

import "testing"

func TestExtractCrateNameVersion(t *testing.T) {
	cases := []struct {
		title   string
		name    string
		version string
	}{
		{"serde 1.0.200", "serde", "1.0.200"},
		{"my-crate 0.2.1-beta", "my-crate", "0.2.1-beta"},
		{"orphaned-crate", "orphaned-crate", ""},
	}
	for _, tc := range cases {
		n, v := extractCrateNameVersion(tc.title)
		if n != tc.name || v != tc.version {
			t.Errorf("extractCrateNameVersion(%q) = (%q, %q), want (%q, %q)",
				tc.title, n, v, tc.name, tc.version)
		}
	}
}
