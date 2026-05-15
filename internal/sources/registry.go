package sources

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/sources/attackerkb"
	"github.com/dragnet-dev/dragnet/internal/sources/eol_date"
	"github.com/dragnet-dev/dragnet/internal/sources/github_actions"
	"github.com/dragnet-dev/dragnet/internal/sources/huggingface"
	"github.com/dragnet-dev/dragnet/internal/sources/trivy_db"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/aikido"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/blackfog"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/bleepingcomputer"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/corvus"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/coveware"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/dfir_report"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/elastic_labs"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/emsisoft"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/eset"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/greynoise"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/horizon3"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/malwarebytes"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/microsoft_sec"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/phylum"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/polyswarm"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/project_zero"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/proofpoint"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/rapid7"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/red_canary"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/secureworks"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/sekoia"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/socket"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/sonatype"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/stepsecurity"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/talos"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/tenable"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/unit42"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/watchtowr"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs/wiz"
	"github.com/dragnet-dev/dragnet/internal/sources/cisa"
	"github.com/dragnet-dev/dragnet/internal/sources/deps_dev"
	"github.com/dragnet-dev/dragnet/internal/sources/ghsa"
	"github.com/dragnet-dev/dragnet/internal/sources/msrc"
	"github.com/dragnet-dev/dragnet/internal/sources/nvd"
	"github.com/dragnet-dev/dragnet/internal/sources/ossf"
	"github.com/dragnet-dev/dragnet/internal/sources/osv"
	"github.com/dragnet-dev/dragnet/internal/sources/ransomware_live"
	"github.com/dragnet-dev/dragnet/internal/sources/registries/cargo"
	"github.com/dragnet-dev/dragnet/internal/sources/registries/go_modules"
	"github.com/dragnet-dev/dragnet/internal/sources/registries/hex"
	"github.com/dragnet-dev/dragnet/internal/sources/registries/maven"
	"github.com/dragnet-dev/dragnet/internal/sources/registries/npm"
	"github.com/dragnet-dev/dragnet/internal/sources/registries/nuget"
	"github.com/dragnet-dev/dragnet/internal/sources/registries/packagist"
	"github.com/dragnet-dev/dragnet/internal/sources/registries/pub"
	"github.com/dragnet-dev/dragnet/internal/sources/registries/pypi"
	"github.com/dragnet-dev/dragnet/internal/sources/registries/rubygems"
	"github.com/dragnet-dev/dragnet/internal/sources/snyk"
	"github.com/dragnet-dev/dragnet/internal/sources/vulncheck"
)

// All returns one instance of every registered intelligence source.
func All() []Source {
	return []Source{
		// ── Supply: Structured Feeds ────────────────────────────────────────
		osv.New(),
		ghsa.New(),
		ossf.New(),
		cisa.New(),
		// ── Supply: Registry Real-Time Signals ─────────────────────────────
		npm.New(),
		pypi.New(),
		cargo.New(),
		maven.New(),
		nuget.New(),
		rubygems.New(),
		go_modules.New(),
		hex.New(),
		packagist.New(),
		pub.New(),
		// ── Supply: Blog Intel ─────────────────────────────────────────────
		blogs.NewClient(wiz.New()),
		blogs.NewClient(socket.New()),
		blogs.NewClient(aikido.New()),
		blogs.NewClient(stepsecurity.New()),
		blogs.NewClient(sonatype.New()),
		blogs.NewClient(phylum.New()),
		// ── Supply: API Intel ──────────────────────────────────────────────
		snyk.New(),
		deps_dev.New(),
		github_actions.New(filepath.Join("state", "popular_actions.json")),
		huggingface.New(filepath.Join("state", "popular_models.json")),
		// ── Malware: Blog Intel ────────────────────────────────────────────
		blogs.NewClient(polyswarm.New()),
		blogs.NewClient(dfir_report.New()),
		blogs.NewClient(elastic_labs.New()),
		blogs.NewClient(unit42.New()),
		blogs.NewClient(red_canary.New()),
		blogs.NewClient(talos.New()),
		blogs.NewClient(eset.New()),
		blogs.NewClient(sekoia.New()),
		blogs.NewClient(proofpoint.New()),
		blogs.NewClient(malwarebytes.New()),
		// ── Ransomware: Sources ────────────────────────────────────────────
		ransomware_live.New(),
		blogs.NewClient(secureworks.New()),
		blogs.NewClient(microsoft_sec.New()),
		blogs.NewClient(bleepingcomputer.New()),
		blogs.NewClient(emsisoft.New()),
		blogs.NewClient(coveware.New()),
		blogs.NewClient(blackfog.New()),
		blogs.NewClient(corvus.New()),
		// ── CVE: Sources ───────────────────────────────────────────────────
		nvd.New(),
		msrc.New(),
		blogs.NewClient(project_zero.New()),
		blogs.NewClient(rapid7.New()),
		attackerkb.New(),
		blogs.NewClient(greynoise.New()),
		blogs.NewClient(horizon3.New()),
		blogs.NewClient(watchtowr.New()),
		blogs.NewClient(tenable.New()),
		vulncheck.New(),
		// ── Container: Sources ────────────────────────────────────────────
		// trivy_db uses "state/trivy_cache" as the default cache directory.
		// Popular image filtering is applied post-fetch in cmd/sync.go.
		trivy_db.New("state/trivy_cache", nil),
		eol_date.New(),
	}
}

// ByName returns only the sources whose Name() matches one of the given names.
// It returns an error if any name has no corresponding registered source.
func ByName(names []string) ([]Source, error) {
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}
	var out []Source
	for _, s := range All() {
		if nameSet[s.Name()] {
			delete(nameSet, s.Name())
			out = append(out, s)
		}
	}
	if len(nameSet) > 0 {
		unknown := make([]string, 0, len(nameSet))
		for n := range nameSet {
			unknown = append(unknown, n)
		}
		return nil, fmt.Errorf("unknown source(s): %s", strings.Join(unknown, ", "))
	}
	return out, nil
}

// ForModule returns sources enabled in the module's source map from dragnet.yaml.
func ForModule(enabled map[string]bool) ([]Source, error) {
	var names []string
	for name, on := range enabled {
		if on {
			names = append(names, name)
		}
	}
	return ByName(names)
}
