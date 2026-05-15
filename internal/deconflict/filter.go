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
// as domains by reGenericDefangedDomain). Also rejects bare single-label values.
func Domain(s string) bool {
	if IP(s) {
		return true
	}
	// Reject bare TLDs / single-label values with no dot
	if !strings.Contains(s, ".") {
		return true
	}
	return false
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
