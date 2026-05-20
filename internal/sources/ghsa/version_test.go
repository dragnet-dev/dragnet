package ghsa

import (
	"reflect"
	"testing"
)

func TestParseVersionRange(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{">=1.0, <2.0", []string{">=1.0", "<2.0"}},
		{"= 1.2.3", []string{"= 1.2.3"}},
		{">= 0, < 3.14.0", []string{">= 0", "< 3.14.0"}},
		{"", nil},
	}
	for _, tc := range cases {
		got := parseVersionRange(tc.input)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseVersionRange(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}
