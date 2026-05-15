package blogs

import "testing"

func TestNormalizeIOC(t *testing.T) {
	tests := []struct {
		typ, raw string
		wantVal  string
		wantOK   bool
	}{
		// IP: extract bare IP from annotated cell text
		{"ip", "C2 IP · 142.11.206.73", "142.11.206.73", true},
		{"ip", "DNS C2 sink: 37.16.75.69 (UDP 53) -- doubles as sink", "37.16.75.69", true},
		{"ip", "94.154.172.43", "94.154.172.43", true},
		{"ip", "no ip here", "", false},
		{"ip", "", "", false},
		// URL: strip trailing annotation, require http(s) scheme
		{"url", "https://evil.com (exfil endpoint)", "https://evil.com", true},
		{"url", "http://c2.net/beacon?id=1 (C2 node)", "http://c2.net/beacon?id=1", true},
		{"url", "https://clean.example.com/path", "https://clean.example.com/path", true},
		{"url", "not-a-url", "", false},
		{"url", "ftp://wrong-scheme.com", "", false},
		{"url", "", "", false},
		// Domain: reject strings with annotation characters
		{"domain", "git-tanstack.com", "git-tanstack.com", true},
		{"domain", "C2 domain · evil.com", "", false},
		{"domain", "evil.com (annotation)", "", false},
		{"domain", "evil.com:8080", "", false},
		{"domain", "", "", false},
		// Default: passthrough non-empty, reject empty
		{"sha256", "abc123def456", "abc123def456", true},
		{"sha256", "", "", false},
	}
	for _, tt := range tests {
		val, ok := NormalizeIOC(tt.typ, tt.raw)
		if ok != tt.wantOK || (ok && val != tt.wantVal) {
			t.Errorf("NormalizeIOC(%q, %q) = (%q, %v), want (%q, %v)",
				tt.typ, tt.raw, val, ok, tt.wantVal, tt.wantOK)
		}
	}
}
