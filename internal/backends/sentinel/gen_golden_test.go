//go:build gen_golden

package sentinel_test

import (
	"os"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/backends/sentinel"
)

func TestGenSentinelGolden(t *testing.T) {
	files := []struct{ input, output string }{
		{"testdata/input_network.sigma.yaml", "testdata/golden_network.yaml"},
		{"testdata/input_process.sigma.yaml", "testdata/golden_process.yaml"},
	}
	b := sentinel.New()
	for _, f := range files {
		data, err := os.ReadFile(f.input)
		if err != nil {
			t.Fatalf("read %s: %v", f.input, err)
		}
		out, err := b.Compile(data)
		if err != nil {
			t.Fatalf("compile %s: %v", f.input, err)
		}
		if err := os.WriteFile(f.output, out, 0644); err != nil {
			t.Fatalf("write %s: %v", f.output, err)
		}
		t.Logf("wrote %s:\n%s", f.output, string(out))
	}
}
