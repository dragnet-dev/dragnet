package typosquat

import (
	"strings"
	"unicode"

	"github.com/dragnet-dev/dragnet/internal/popularity"
)

// TyposquatMatch describes a potential typosquat detected against a popular package.
type TyposquatMatch struct {
	NewPackage      string
	TargetPackage   string
	TargetDownloads int64
	TargetImpact    string
	SimilarityScore float64
	Technique       string
}

// Detect checks newPkg against the popular packages list and returns the best match
// if its similarity score meets threshold (0.0–1.0). Returns nil if no match.
func Detect(newPkg string, popular []popularity.PopularPackage, threshold float64) *TyposquatMatch {
	newLow := strings.ToLower(newPkg)
	var best *TyposquatMatch
	for _, p := range popular {
		targetLow := strings.ToLower(p.Name)
		if newLow == targetLow {
			continue
		}
		score, technique := similarity(newLow, targetLow)
		if score >= threshold {
			if best == nil || score > best.SimilarityScore {
				m := &TyposquatMatch{
					NewPackage:      newPkg,
					TargetPackage:   p.Name,
					TargetDownloads: p.WeeklyDownloads,
					TargetImpact:    p.ImpactRating,
					SimilarityScore: score,
					Technique:       technique,
				}
				best = m
			}
		}
	}
	return best
}

// similarity returns a 0–1 score and technique name for the most applicable
// similarity between a and b (both already lowercased).
func similarity(a, b string) (float64, string) {
	// 1. Homoglyph check — replace look-alike unicode chars and compare
	if normaliseHomoglyphs(a) == normaliseHomoglyphs(b) {
		return 0.99, "homoglyph"
	}

	// 2. Prefix-scope stripping — remove @scope/ from npm-style names
	a2 := stripScope(a)
	b2 := stripScope(b)
	if a2 != a || b2 != b {
		if a2 == b2 {
			return 0.95, "prefix_scope"
		}
	}

	// 3. Suffix/prefix addition — lodash-dev vs lodash
	if isAddition(a, b) {
		return 0.85, "addition"
	}

	// 4. Edit-distance (omission, substitution, swap) on packages of length >= 4
	maxLen := len(b)
	if len(a) > maxLen {
		maxLen = len(a)
	}
	if maxLen < 4 {
		return 0.0, ""
	}
	d := levenshtein(a, b)
	if len(b) >= 5 && d <= 2 {
		score := 1.0 - float64(d)/float64(maxLen)
		technique := editTechnique(a, b, d)
		return score, technique
	}
	if len(b) >= 4 && d == 1 {
		score := 1.0 - 1.0/float64(maxLen)
		technique := editTechnique(a, b, d)
		return score, technique
	}

	return 0.0, ""
}

// editTechnique classifies a single edit as omission, substitution, or swap.
func editTechnique(a, b string, d int) string {
	if d == 1 {
		la, lb := len(a), len(b)
		if la == lb+1 {
			return "omission"
		}
		if la+1 == lb {
			return "omission"
		}
		// same length → substitution
		return "substitution"
	}
	// Check for transposition (swap)
	if len(a) == len(b) {
		diffs := 0
		for i := range a {
			if a[i] != b[i] {
				diffs++
			}
		}
		if diffs == 2 {
			return "swap"
		}
	}
	return "substitution"
}

// isAddition returns true when one string is the other with a suffix/prefix appended.
func isAddition(a, b string) bool {
	separators := []string{"-", "_", "."}
	for _, sep := range separators {
		if strings.HasPrefix(a, b+sep) || strings.HasSuffix(a, sep+b) {
			return true
		}
		if strings.HasPrefix(b, a+sep) || strings.HasSuffix(b, sep+a) {
			return true
		}
	}
	return false
}

// stripScope removes the @scope/ prefix from npm package names.
func stripScope(s string) string {
	if strings.HasPrefix(s, "@") {
		if idx := strings.Index(s, "/"); idx != -1 {
			return s[idx+1:]
		}
	}
	return s
}

// homoglyphMap maps unicode lookalikes to their ASCII equivalents.
var homoglyphMap = map[rune]rune{
	'о': 'o', 'О': 'o', 'а': 'a', 'е': 'e', 'с': 'c',
	'р': 'p', 'у': 'y', 'х': 'x', 'і': 'i', 'ı': 'i',
	'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
}

func normaliseHomoglyphs(s string) string {
	var b strings.Builder
	for _, r := range s {
		if rep, ok := homoglyphMap[r]; ok {
			b.WriteRune(rep)
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

func levenshtein(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i, ca := range a {
		curr[0] = i + 1
		for j, cb := range b {
			if ca == cb {
				curr[j+1] = prev[j]
			} else {
				curr[j+1] = 1 + min3(prev[j], prev[j+1], curr[j])
			}
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
