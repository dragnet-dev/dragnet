package typosquat

import (
	"strings"
	"sync"
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

// normalizedPkg caches the pre-computed forms of a popular package used during
// detection so normaliseHomoglyphs is not called on the target side per-check.
type normalizedPkg struct {
	pkg           popularity.PopularPackage
	lowName       string
	homoglyphNorm string
}

// Detector holds a pre-processed popular-packages list for repeated detection
// calls. Construct once per ecosystem per sync cycle via NewDetector, then call
// Detect for each new package name.
type Detector struct {
	popular   []normalizedPkg
	threshold float64
}

// NewDetector normalizes popular once and returns a Detector ready for reuse.
func NewDetector(popular []popularity.PopularPackage, threshold float64) *Detector {
	norms := make([]normalizedPkg, len(popular))
	for i, p := range popular {
		low := strings.ToLower(p.Name)
		norms[i] = normalizedPkg{p, low, normaliseHomoglyphs(low)}
	}
	return &Detector{popular: norms, threshold: threshold}
}

// Detect checks newPkg against the popular packages list and returns the best
// match if its similarity score meets the threshold. Returns nil if no match.
func (d *Detector) Detect(newPkg string) *TyposquatMatch {
	newLow := strings.ToLower(newPkg)
	newNorm := normaliseHomoglyphs(newLow)
	var best *TyposquatMatch
	for _, p := range d.popular {
		if newLow == p.lowName {
			continue
		}
		score, technique := similarity(newLow, newNorm, p.lowName, p.homoglyphNorm)
		if score >= d.threshold {
			if best == nil || score > best.SimilarityScore {
				m := &TyposquatMatch{
					NewPackage:      newPkg,
					TargetPackage:   p.pkg.Name,
					TargetDownloads: p.pkg.WeeklyDownloads,
					TargetImpact:    p.pkg.ImpactRating,
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
// similarity between a and b (both already lowercased, with pre-computed norms).
func similarity(a, aNorm, b, bNorm string) (float64, string) {
	// 1. Homoglyph check — replace look-alike unicode chars and compare
	if aNorm == bNorm {
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

// levPool reuses the two row-buffer slices across levenshtein calls to
// eliminate per-call heap allocation. The pool stores *[2][]int so both
// rows are returned together in one Put.
var levPool = sync.Pool{New: func() any { return &[2][]int{} }}

func levenshtein(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	bufs := levPool.Get().(*[2][]int)
	n := len(b) + 1
	if cap(bufs[0]) < n {
		bufs[0] = make([]int, n)
	} else {
		bufs[0] = bufs[0][:n]
	}
	if cap(bufs[1]) < n {
		bufs[1] = make([]int, n)
	} else {
		bufs[1] = bufs[1][:n]
	}
	prev, curr := bufs[0], bufs[1]

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
	result := prev[len(b)]

	// Restore canonical slot order before returning to pool.
	bufs[0], bufs[1] = prev, curr
	levPool.Put(bufs)
	return result
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
