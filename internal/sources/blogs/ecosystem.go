package blogs

import "strings"

// ecosystemKeywords maps ecosystem names to their indicator keywords.
var ecosystemKeywords = map[string][]string{
	"npm":       {"npm", "node_modules", "package.json", "yarn", "pnpm"},
	"pypi":      {"pypi", "pip install", "setup.py", "pyproject.toml"},
	"cargo":     {"crates.io", "cargo.toml", "cargo add"},
	"maven":     {"maven", "pom.xml", "mvn", "groupid", "artifactid"},
	"nuget":     {"nuget", "dotnet add package", ".csproj", "nuspec"},
	"rubygems":  {"rubygems", "gem install", "gemfile", ".gemspec"},
	"go":        {"go.mod", "go get", "pkg.go.dev", "golang"},
	"hex":       {"hex.pm", "mix.exs", "elixir", "erlang"},
	"packagist": {"packagist", "composer.json", "composer require"},
	"pub":       {"pub.dev", "pubspec.yaml", "flutter pub"},
}

// InferEcosystems returns the ecosystems mentioned in the given HTML/text content.
func InferEcosystems(content string) []string {
	lower := strings.ToLower(content)
	var found []string
	for ecosystem, keywords := range ecosystemKeywords {
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				found = append(found, ecosystem)
				break
			}
		}
	}
	return found
}
