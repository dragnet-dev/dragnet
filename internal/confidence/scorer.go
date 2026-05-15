package confidence

import (
	"math"
	"time"
)

var sourceWeights = map[string]float64{
	// Supply chain — structured feeds
	"osv":  0.95,
	"ghsa": 0.95,
	"cisa": 0.90,
	"ossf": 0.85,
	// Supply chain — blog parsers
	"wiz":          0.90,
	"socket":       0.90,
	"sonatype":     0.82,
	"phylum":       0.82,
	"aikido":       0.80,
	"stepsecurity": 0.80,
	"snyk":         0.78,
	"deps_dev":     0.75,
	// Malware
	"dfir_report":  0.90,
	"elastic_labs": 0.88,
	"unit42":       0.87,
	"eset":         0.87,
	"red_canary":   0.85,
	"talos":        0.85,
	"sekoia":       0.82,
	"proofpoint":   0.82,
	"malwarebytes": 0.78,
	"polyswarm":    0.78,
	// Ransomware
	"secureworks":     0.88,
	"emsisoft":        0.85,
	"microsoft_sec":   0.80,
	"ransomware_live": 0.80,
	"blackfog":        0.75,
	"coveware":        0.75,
	"corvus":          0.70,
	// CVE
	"nvd":          0.92,
	"msrc":         0.90,
	"project_zero": 0.92,
	"rapid7":       0.85,
	"attackerkb":   0.83,
	"greynoise":    0.82,
	"horizon3":     0.82,
	"watchtowr":    0.82,
	"tenable":      0.80,
	"vulncheck":    0.82,
}

// Calculate returns a confidence score in [0.30, 0.98] for a set of source names.
// The base score is the highest single-source weight; each additional source adds
// 0.08 (up to +0.20 bonus total).
func Calculate(sources []string) float64 {
	if len(sources) == 0 {
		return 0.30
	}
	max := 0.0
	for _, s := range sources {
		if w := sourceWeights[s]; w > max {
			max = w
		}
	}
	bonus := math.Min(float64(len(sources)-1)*0.08, 0.20)
	return math.Min(max+bonus, 0.98)
}

// Decay caps confidence based on incident age so stale IOCs don't run at full
// confidence. >6 months → cap at 0.40; >90 days → cap at 0.70.
func Decay(conf float64, firstSeen time.Time) float64 {
	if firstSeen.IsZero() {
		return conf
	}
	age := time.Since(firstSeen)
	switch {
	case age > 180*24*time.Hour:
		return math.Min(conf, 0.40)
	case age > 90*24*time.Hour:
		return math.Min(conf, 0.70)
	default:
		return conf
	}
}

// Status maps a confidence score to a Sigma rule status string.
// Scores below 0.40 (typically from decay on old incidents) map to "deprecated".
func Status(c float64) string {
	switch {
	case c >= 0.85:
		return "stable"
	case c >= 0.60:
		return "test"
	case c >= 0.40:
		return "experimental"
	default:
		return "deprecated"
	}
}
