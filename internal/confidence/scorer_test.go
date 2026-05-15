package confidence

import (
	"math"
	"testing"
)

func TestCalculate(t *testing.T) {
	tests := []struct {
		sources []string
		want    float64
	}{
		{nil, 0.30},
		{[]string{}, 0.30},
		{[]string{"wiz"}, 0.90},
		{[]string{"osv"}, 0.95},
		{[]string{"wiz", "socket", "aikido"}, 0.98},
		{[]string{"wiz", "socket"}, 0.98}, // 0.90 + 0.08 bonus = 0.98
	}
	for _, tt := range tests {
		got := Calculate(tt.sources)
		if math.Abs(got-tt.want) > 0.001 {
			t.Errorf("Calculate(%v) = %.3f, want %.3f", tt.sources, got, tt.want)
		}
	}
}

func TestStatus(t *testing.T) {
	if Status(0.90) != "stable" {
		t.Error("0.90 should be stable")
	}
	if Status(0.70) != "test" {
		t.Error("0.70 should be test")
	}
	if Status(0.40) != "experimental" {
		t.Error("0.40 should be experimental")
	}
}
