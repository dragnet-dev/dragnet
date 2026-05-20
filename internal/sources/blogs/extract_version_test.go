package blogs

import (
	"fmt"
	"testing"
)

func TestExtractPackages(t *testing.T) {
	cases := []struct {
		name    string
		html    string
		wantPkg string
		wantEco string
		wantVer string
	}{
		{
			name:    "scoped npm no version",
			html:    `<p>The package @solana/web3.js was compromised.</p>`,
			wantPkg: "@solana/web3.js", wantEco: "npm", wantVer: "",
		},
		{
			name:    "scoped npm with version",
			html:    `<p>Attackers published @solana/web3.js@1.95.8 to npm.</p>`,
			wantPkg: "@solana/web3.js", wantEco: "npm", wantVer: "1.95.8",
		},
		{
			name:    "npm install unscoped with version",
			html:    `<code>npm install malicious-pkg@2.0.1</code>`,
			wantPkg: "malicious-pkg", wantEco: "npm", wantVer: "2.0.1",
		},
		{
			name:    "pip install no version",
			html:    `<p>Run pip install requests to get the backdoored version.</p>`,
			wantPkg: "requests", wantEco: "pypi", wantVer: "",
		},
		{
			name:    "pip install with version",
			html:    `<code>pip install requests==2.28.0</code>`,
			wantPkg: "requests", wantEco: "pypi", wantVer: "==2.28.0",
		},
		{
			name:    "pip3 install with version range",
			html:    `<code>pip3 install flask>=2.0,<3.0</code>`,
			wantPkg: "flask", wantEco: "pypi", wantVer: ">=2.0,<3.0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkgs := ExtractPackages(tc.html)
			if len(pkgs) == 0 {
				t.Fatalf("got 0 packages, want %q/%q", tc.wantEco, tc.wantPkg)
			}
			found := false
			for _, p := range pkgs {
				fmt.Printf("  [%s] eco=%s name=%s ver=%q\n", tc.name, p.Ecosystem, p.Name, p.Version)
				if p.Name == tc.wantPkg && p.Ecosystem == tc.wantEco {
					found = true
					if p.Version != tc.wantVer {
						t.Errorf("version: got %q, want %q", p.Version, tc.wantVer)
					}
				}
			}
			if !found {
				t.Errorf("package %q/%q not found in %+v", tc.wantEco, tc.wantPkg, pkgs)
			}
		})
	}
}
