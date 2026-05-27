package iocutil_test

import (
	"testing"

	"github.com/dragnet-dev/dragnet/internal/iocutil"
)

func TestNormalize_HashCases(t *testing.T) {
	cases := []struct {
		typ    string
		value  string
		wantOK bool
	}{
		// Empty-file hashes must be rejected
		{"sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false},
		{"sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", false},
		{"md5", "d41d8cd98f00b204e9800998ecf8427e", false},
		// Real hashes must be accepted
		{"sha256", "abc123def456", true},
		{"sha1", "deadbeefcafe", true},
		{"md5", "cafebabe1234", true},
	}

	for _, c := range cases {
		_, ok := iocutil.Normalize(c.typ, c.value)
		if ok != c.wantOK {
			t.Errorf("Normalize(%q, %q) ok=%v, want %v", c.typ, c.value, ok, c.wantOK)
		}
	}
}
