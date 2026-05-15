package aikido

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
		{"file_name", "router_init.js"},
		{"sha256", "ab4fcadaec1d282b900de5abb5b1d55dbd0e7af9628f6e7a5e2cb0e68b3b56aa"},
		{"sha256", "2ec78d55aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd"},
		{"file_name", "@tanstack/setup"},
		{"git_dep", "github:tanstack/router#79ac49ee6b59a9a0d00d5b7c9e1d2b3a4c5d6e7f"},
		{"url", "http://filev2.getsession.org/file/"},
		{"url", "https://cdn.evil.example.com/payload"},
		{"ip", "83.142.209.194"},
		{"campaign_marker", "A Mini Shai-Hulud has Appeared"},
	}

	for _, w := range want {
		if !hasIOC(iocs, w.iocType, w.value) {
			t.Errorf("missing IOC type=%q value=%q", w.iocType, w.value)
		}
	}

	// Verify Source
	for _, ioc := range iocs {
		if ioc.Source != "aikido" {
			t.Errorf("expected source=aikido, got %q", ioc.Source)
		}
	}
}

func TestName(t *testing.T) {
	p := New()
	if p.Name() != "aikido" {
		t.Errorf("expected name=aikido, got %q", p.Name())
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
