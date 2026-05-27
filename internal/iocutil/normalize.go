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
	case "sha256":
		if raw == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
			return "", false // Empty file hash
		}
		return raw, true
	case "sha1":
		if raw == "da39a3ee5e6b4b0d3255bfef95601890afd80709" {
			return "", false // Empty file hash
		}
		return raw, true
	case "md5":
		if raw == "d41d8cd98f00b204e9800998ecf8427e" {
			return "", false // Empty file hash
		}
		return raw, true
	default:
		return raw, raw != ""
	}
}

// falsePositiveWords is a conservative denylist of strings that are definitely
// not package names — English prepositions, conjunctions, articles, pronouns,
// and a handful of HTML/prose tokens. It deliberately excludes short strings
// that ARE real packages (pg, ws, rc, got, tar, mem, uv, ai, etc.).
var falsePositiveWords = map[string]bool{
	// articles / prepositions / conjunctions
	"a": true, "an": true, "the": true, "of": true, "in": true, "on": true,
	"at": true, "by": true, "to": true, "or": true, "if": true, "as": true,
	"up": true, "no": true, "so": true, "and": true, "but": true, "nor": true,
	"for": true, "yet": true, "via": true, "per": true, "vs": true,
	// pronouns
	"i": true, "me": true, "my": true, "we": true, "us": true, "our": true,
	"he": true, "his": true, "him": true, "she": true, "her": true,
	"it": true, "its": true, "they": true, "them": true, "their": true,
	"you": true, "your": true, "who": true, "whom": true, "that": true,
	"this": true, "these": true, "those": true, "which": true,
	// common verbs / adverbs that appear in prose near install commands
	"is": true, "are": true, "was": true, "were": true, "be": true,
	"been": true, "being": true, "have": true, "has": true, "had": true,
	"do": true, "does": true, "did": true, "will": true, "would": true,
	"can": true, "could": true, "may": true, "might": true, "shall": true,
	"should": true, "must": true, "not": true, "now": true, "then": true,
	"also": true, "just": true, "only": true, "even": true, "both": true,
	"each": true, "more": true, "most": true, "than": true, "when": true,
	"with": true, "from": true, "into": true, "onto": true, "upon": true,
	"after": true, "again": true, "still": true, "about": true, "above": true,
	"below": true, "under": true, "over": true, "back": true, "such": true,
	"well": true, "very": true, "here": true, "there": true, "where": true,
	"why": true, "what": true, "how": true, "some": true, "because": true,
	"while": true, "until": true, "unless": true, "since": true, "against": true,
	"else": true, "like": true,
	// misc prose / HTML tokens
	"null": true, "true": true, "false": true, "none": true,
	"div": true, "span": true, "href": true, "http": true, "https": true,
	"id": true, "class": true, "style": true, "type": true,
	"all": true, "any": true, "one": true, "two": true, "new": true,
	"old": true, "out": true, "off": true, "own": true,
	"see": true, "try": true, "let": true, "run": true, "use": true,
	"set": true, "get": true, "add": true,
	// Note: "put" is a real npm package with a documented HackerOne CVE — deliberately excluded.
	// Common programming code snippet variables that pollute the pip parser
	"version": true, "count": true, "length": true, "status": true, "value": true,
	"index": true, "result": true, "error": true, "req": true, "res": true,
	"user": true, "admin": true, "password": true, "key": true, "token": true,
	"size": true, "width": true, "height": true, "return": true, "break": true,
	"continue": true, "switch": true, "case": true, "default": true, "import": true,
	"export": true, "require": true, "module": true, "struct": true, "func": true,
	"def": true, "function": true, "github.com": true,
}

// reTrailingPunct matches names that end with a punctuation character that
// no real package manager permits at the end of a name (. , ; ! ?).
var reTrailingPunct = regexp.MustCompile(`[.,;!?]$`)

// reSpaces matches names containing a whitespace character — prose fragments.
var reSpaces = regexp.MustCompile(`\s`)

// IsFalsePkgName returns true when name is a parser false positive.
func IsFalsePkgName(name string) bool {
	if name == "" {
		return true
	}
	// Names longer than 100 chars are SEO-spam or truncated module paths, not packages.
	if len(name) > 100 {
		return true
	}
	if reSpaces.MatchString(name) {
		return true
	}
	if reTrailingPunct.MatchString(name) {
		return true
	}
	if falsePositiveWords[strings.ToLower(name)] {
		return true
	}
	return false
}
