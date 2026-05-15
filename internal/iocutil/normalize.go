// Package iocutil holds IOC string-cleaning helpers shared by sources and
// downstream consumers (the Sigma generator) so we have one canonical
// "cleaned + deconflicted" path. Previously this lived in two near-identical
// copies in internal/sigma and internal/sources/blogs that drifted.
package iocutil

import (
	"regexp"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/deconflict"
)

var (
	reIP             = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reURLTrailing    = regexp.MustCompile(`\s+.*$`)
)

// Normalize cleans a raw IOC value (typically extracted from a blog post or
// a cached indicator). It applies the deconflict allowlists so that
// well-known infrastructure (Google DNS, RFC1918 ranges, etc.) is rejected
// rather than emitted as a malicious IOC.
//
// Returns ("", false) when the value should be discarded.
func Normalize(typ, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	switch typ {
	case "ip":
		ip := reIP.FindString(raw)
		if ip == "" || deconflict.IP(ip) {
			return "", false
		}
		return ip, true
	case "url":
		clean := strings.TrimSpace(reURLTrailing.ReplaceAllString(raw, ""))
		if !strings.HasPrefix(clean, "http://") && !strings.HasPrefix(clean, "https://") {
			return "", false
		}
		if deconflict.URL(clean) {
			return "", false
		}
		return clean, true
	case "domain":
		if strings.ContainsAny(raw, " \t·:") {
			return "", false
		}
		if deconflict.Domain(raw) {
			return "", false
		}
		return raw, true
	default:
		return raw, raw != ""
	}
}
