package stix

import "fmt"

func DomainPattern(domain string) string {
	return fmt.Sprintf("[domain-name:value = '%s']", domain)
}

func IPv4Pattern(ip string) string {
	return fmt.Sprintf("[ipv4-addr:value = '%s']", ip)
}

func IPv6Pattern(ip string) string {
	return fmt.Sprintf("[ipv6-addr:value = '%s']", ip)
}

func URLPattern(u string) string {
	return fmt.Sprintf("[url:value = '%s']", u)
}

func SHA256Pattern(hash string) string {
	return fmt.Sprintf("[file:hashes.SHA256 = '%s']", hash)
}

func SHA1Pattern(hash string) string {
	return fmt.Sprintf("[file:hashes.SHA1 = '%s']", hash)
}

func MD5Pattern(hash string) string {
	return fmt.Sprintf("[file:hashes.MD5 = '%s']", hash)
}

func FileNamePattern(name string) string {
	return fmt.Sprintf("[file:name = '%s']", name)
}

func ServicePattern(name string) string {
	return fmt.Sprintf("[process:name = '%s']", name)
}

// FilePathPattern matches a file by its full path in the file:name field.
// Using file:name with a full path is a practical simplification — the spec-correct
// form requires a directory SCO reference, but this is what SIEMs and threat
// platforms actually accept for file path indicators.
func FilePathPattern(path string) string {
	return fmt.Sprintf("[file:name = '%s']", path)
}

// hashPattern dispatches to the correct hash pattern function by algorithm name.
func hashPattern(algorithm, value string) string {
	switch algorithm {
	case "sha256":
		return SHA256Pattern(value)
	case "sha1":
		return SHA1Pattern(value)
	case "md5":
		return MD5Pattern(value)
	default:
		return fmt.Sprintf("[file:hashes.'%s' = '%s']", algorithm, value)
	}
}
