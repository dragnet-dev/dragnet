package stepsecurity

import (
	"os"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/sources/blogs"
)

func TestParseIOCs(t *testing.T) {
	data, err := os.ReadFile("testdata/post.html")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	p := New()
	iocs, _, err := p.ParseIOCs(string(data))
	if err != nil {
		t.Fatalf("ParseIOCs error: %v", err)
	}
	if len(iocs) == 0 {
		t.Fatal("expected IOCs, got none")
	}

	type check struct {
		iocType string
		value   string
	}
	want := []check{
		{"file_name", "malicious_action.js"},
		{"sha256", "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"},
		{"sha256", "cafebabe1234567890abcdef1234567890abcdef1234567890abcdef12345678"},
		{"url", "https://attacker.evil.example.com/collect"},
		{"url", "http://c2.malware.example.com/cmd"},
		{"ip", "192.168.100.200"},
		{"campaign_marker", "Operation GitSlurp"},
	}

	for _, w := range want {
		if !hasIOC(iocs, w.iocType, w.value) {
			t.Errorf("missing IOC type=%q value=%q", w.iocType, w.value)
		}
	}

	// Verify Source
	for _, ioc := range iocs {
		if ioc.Source != "stepsecurity" {
			t.Errorf("expected source=stepsecurity, got %q", ioc.Source)
		}
	}
}

func TestName(t *testing.T) {
	p := New()
	if p.Name() != "stepsecurity" {
		t.Errorf("expected name=stepsecurity, got %q", p.Name())
	}
}

func TestMatchesPost(t *testing.T) {
	p := New()
	if !p.MatchesPost("Malicious npm package discovered", "") {
		t.Error("expected match for npm package")
	}
	if p.MatchesPost("Hello World blog post", "") {
		t.Error("unexpected match for unrelated post")
	}
}

func hasIOC(iocs []blogs.RawIOC, iocType, value string) bool {
	for _, ioc := range iocs {
		if ioc.Type == iocType && ioc.Value == value {
			return true
		}
	}
	return false
}
