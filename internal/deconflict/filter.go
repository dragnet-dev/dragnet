package deconflict

import (
	"net"
	"net/url"
	"strings"
)

var blockedCIDRs = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range []string{
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local / cloud IMDS
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 ULA
		"fe80::/10",      // IPv6 link-local
	} {
		_, n, _ := net.ParseCIDR(cidr)
		if n != nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

var blockedExact = map[string]bool{
	"8.8.8.8": true, "8.8.4.4": true,
	"1.1.1.1": true, "1.0.0.1": true,
	"9.9.9.9": true,
}

// IP returns true when s is an IP address that should be suppressed from Sigma
// rules and IOC feeds (private ranges, loopback, link-local, public DNS resolvers).
func IP(s string) bool {
	parsed := net.ParseIP(s)
	if parsed == nil {
		return false
	}
	if blockedExact[s] {
		return true
	}
	for _, cidr := range blockedCIDRs {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// Domain returns true when s should be suppressed as a domain indicator.
// Rejects values that parse as blocked IPs (catches defanged IPs misclassified
// as domains by reGenericDefangedDomain). Also rejects bare single-label values,
// known file extensions, and common benign domains.
func Domain(s string) bool {
	if IP(s) {
		return true
	}
	// Reject bare TLDs / single-label values with no dot
	if !strings.Contains(s, ".") {
		return true
	}

	s = strings.ToLower(s)
	tld := s[strings.LastIndex(s, ".")+1:]
	switch tld {
	case "example", "invalid", "localhost", "local", "test":
		return true
	}

	// Reject if the "domain" ends with a common file extension.
	// Defanged file names (e.g. malware[.]exe) often get parsed as domains.
	for _, ext := range fileExtensions {
		if strings.HasSuffix(s, ext) {
			return true
		}
	}

	// Reject common benign domains
	if blockedDomains[s] {
		return true
	}
	for _, suffix := range blockedDomainSuffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}

	return false
}

var fileExtensions = []string{
	".exe", ".dll", ".sys", ".drv", ".ocx", ".cpl", ".scr", // Windows PE
	".bash", ".zsh", ".elf", ".bin", // Linux/Unix
	".bat", ".cmd", ".ps1", ".vbs", // Scripts
	".py", ".js", ".php", ".rb", ".java", // Source
	".json", ".dat", // Data/config files
	".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", // Docs
	".tar", ".gz", ".tgz", ".rar", ".7z", // Archives
	".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", // Images
}

var blockedDomains = map[string]bool{
	"github.com": true, "www.github.com": true,
	"google.com": true, "www.google.com": true,
	"microsoft.com": true, "www.microsoft.com": true,
	"apple.com": true, "www.apple.com": true,
	"amazon.com": true, "www.amazon.com": true,
	"cloudflare.com": true, "www.cloudflare.com": true,
	"youtube.com": true, "www.youtube.com": true,
	"twitter.com": true, "www.twitter.com": true,
	"linkedin.com": true, "www.linkedin.com": true,
	"reddit.com": true, "www.reddit.com": true,
	"wikipedia.org": true, "en.wikipedia.org": true,
	"example.com": true, "example.org": true, "example.net": true,
	"schema.org": true, "w3.org": true,
	"stackoverflow.com": true, "www.stackoverflow.com": true,
	"npmjs.com": true, "www.npmjs.com": true, "registry.npmjs.org": true,
	"pypi.org": true, "www.pypi.org": true,
	"crates.io": true, "www.crates.io": true,
	"hub.docker.com": true, "pkg.go.dev": true,
	"ubuntu.com": true, "debian.org": true,
	"redhat.com": true, "centos.org": true,
	"elastic.co": true, "virustotal.com": true,
	"mitre.org": true, "attack.mitre.org": true,
	"cve.org": true, "nvd.nist.gov": true,
	"raw.githubusercontent": true, "raw.githubusercontent.com": true,
	"bitbucket.org":    true,
	"drive.google.com": true,
	"ipinfo.io":        true,
	"outlook.com":      true,
	"zohomail.com":     true,
}

var blockedDomainSuffixes = []string{
	".blockscout.com",
	// Truncated platform hosts and parser/table artifacts. The real services
	// use longer registrable domains, e.g. trycloudflare.com or workers.dev.
	".trycloudflare",
	".workers",
	".worf",
	".ceye",
	".dnslog",
	".zap",
	".qpon",
	".tyk",
	".nnnwin",
	".nanguanglu",
	".quidoaehse",
	".xidyuyedg",
	".shlowcarbon",
	".incometax",
}

// URL returns true when the URL's host is a blocked IP or domain.
func URL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	return IP(host) || Domain(host)
}
