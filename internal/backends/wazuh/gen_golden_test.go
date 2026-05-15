//go:build gen_golden

package wazuh_test

import (
	"os"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/backends/wazuh"
)

func TestGenGolden(t *testing.T) {
	files := []struct{ input, output string }{
		{"testdata/input_network.sigma.yaml", "testdata/golden_network.xml"},
		{"testdata/input_process.sigma.yaml", "testdata/golden_process.xml"},
		{"testdata/input_file.sigma.yaml", "testdata/golden_file.xml"},
	}
	b := wazuh.New()
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
		t.Logf("wrote %s", f.output)
	}
}
