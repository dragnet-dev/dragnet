//go:build gen_golden

package crowdstrike_test

import (
	"os"
	"testing"

	"github.com/dragnet-dev/dragnet/internal/backends/crowdstrike"
)

func TestGenGolden(t *testing.T) {
	lsFiles := []struct{ input, output string }{
		{"testdata/input_network.sigma.yaml", "testdata/golden_logscale_network.lqs"},
		{"testdata/input_process.sigma.yaml", "testdata/golden_logscale_process.lqs"},
		{"testdata/input_file.sigma.yaml", "testdata/golden_logscale_file.lqs"},
	}
	ls := crowdstrike.NewLogScale()
	for _, f := range lsFiles {
		data, err := os.ReadFile(f.input)
		if err != nil {
			t.Fatalf("read %s: %v", f.input, err)
		}
		out, err := ls.Compile(data)
		if err != nil {
			t.Fatalf("compile %s: %v", f.input, err)
		}
		if err := os.WriteFile(f.output, out, 0644); err != nil {
			t.Fatalf("write %s: %v", f.output, err)
		}
		t.Logf("wrote %s", f.output)
	}

	iocFiles := []struct{ input, output string }{
		{"testdata/input_network.sigma.yaml", "testdata/golden_ioc_network.json"},
		{"testdata/input_file.sigma.yaml", "testdata/golden_ioc_file.json"},
	}
	ioc := crowdstrike.NewIOC("detect")
	for _, f := range iocFiles {
		data, err := os.ReadFile(f.input)
		if err != nil {
			t.Fatalf("read %s: %v", f.input, err)
		}
		out, err := ioc.Compile(data)
		if err != nil {
			t.Fatalf("compile %s: %v", f.input, err)
		}
		if err := os.WriteFile(f.output, out, 0644); err != nil {
			t.Fatalf("write %s: %v", f.output, err)
		}
		t.Logf("wrote %s", f.output)
	}
}
