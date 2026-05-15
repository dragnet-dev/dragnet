package wiz

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
		{"sha256", "ab4fcadaec1d282b900de5abb5b1d55dbd0e7af9628f6e7a5e2cb0e68b3b56aa"},
		{"sha1", "12ed9a3cab1b2e3d4f5a6b7c8d9e0f1a2b3c4d5e"},
		{"md5", "833fd59e4b3c2a1d5e6f7a8b9c0d1234"},
		{"domain", "git-tanstack.com"},
		{"ip", "83.142.209.194"},
		{"url", "http://git-tanstack.com/payload.sh"},
		{"service", "gh-token-monitor"},
		{"macos_persistence", "~/Library/LaunchAgents/com.apple.ghmonitor.plist"},
		{"linux_persistence", "/etc/systemd/system/gh-monitor.service"},
		{"file_name", "tanstack_runner.js"},
		{"ide_artifact", "~/.vscode/extensions/tanstack.extension"},
	}

	for _, w := range want {
		if !hasIOC(iocs, w.iocType, w.value) {
			t.Errorf("missing IOC type=%q value=%q", w.iocType, w.value)
		}
	}

	// Verify Source is set correctly
	for _, ioc := range iocs {
		if ioc.Source != "wiz" {
			t.Errorf("expected source=wiz, got %q", ioc.Source)
		}
	}
}

func TestName(t *testing.T) {
	p := New()
	if p.Name() != "wiz" {
		t.Errorf("expected name=wiz, got %q", p.Name())
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
