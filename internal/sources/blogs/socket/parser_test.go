package socket

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
		iocType  string
		value    string
		filename string
	}
	want := []check{
		{"sha256", "ab4fcadaec1d282b900de5abb5b1d55dbd0e7af9628f6e7a5e2cb0e68b3b56aa", "router_init.js"},
		{"sha1", "12ed9a3cab1b2e3d4f5a6b7c8d9e0f1a2b3c4d5e", "router_init.js"},
		{"md5", "833fd59e4b3c2a1d5e6f7a8b9c0d1234", "router_init.js"},
		{"sha256", "2ec78d55aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd1a", "tanstack_runner.js"},
		{"url", "http://filev2.getsession.org/file/payload.sh", ""},
		{"url", "https://cdn.evil.example.com/stage2.bin", ""},
		{"ip", "83.142.209.194", ""},
		{"domain", "malware-c2.example.com", ""},
	}

	for _, w := range want {
		if !hasIOCWithFile(iocs, w.iocType, w.value, w.filename) {
			t.Errorf("missing IOC type=%q value=%q filename=%q", w.iocType, w.value, w.filename)
		}
	}

	// Make sure the "DO NOT BLOCK" IP was skipped
	if hasIOC(iocs, "ip", "169.254.169.254") {
		t.Error("should not include DO NOT BLOCK IP 169.254.169.254")
	}

	// Verify Source
	for _, ioc := range iocs {
		if ioc.Source != "socket" {
			t.Errorf("expected source=socket, got %q", ioc.Source)
		}
	}
}

func TestName(t *testing.T) {
	p := New()
	if p.Name() != "socket" {
		t.Errorf("expected name=socket, got %q", p.Name())
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

func hasIOCWithFile(iocs []blogs.RawIOC, iocType, value, filename string) bool {
	for _, ioc := range iocs {
		if ioc.Type == iocType && ioc.Value == value {
			if filename == "" || ioc.Filename == filename {
				return true
			}
		}
	}
	return false
}
