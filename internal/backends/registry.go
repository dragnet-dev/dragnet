package backends

import (
	"fmt"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/backends/chronicle"
	"github.com/dragnet-dev/dragnet/internal/backends/crowdstrike"
	"github.com/dragnet-dev/dragnet/internal/backends/datadog"
	"github.com/dragnet-dev/dragnet/internal/backends/elastic"
	"github.com/dragnet-dev/dragnet/internal/backends/kql"
	"github.com/dragnet-dev/dragnet/internal/backends/qradar"
	"github.com/dragnet-dev/dragnet/internal/backends/sentinel"
	"github.com/dragnet-dev/dragnet/internal/backends/snort"
	"github.com/dragnet-dev/dragnet/internal/backends/splunk"
	"github.com/dragnet-dev/dragnet/internal/backends/suricata"
	"github.com/dragnet-dev/dragnet/internal/backends/wazuh"
)

// All returns the default backend set for `--backends all`.
//
// crowdstrike-ioc and datadog are intentionally excluded from the default
// (v0.1.15+): both emit pure IOC lists (hash/domain/IP) which duplicate
// the data already in feeds/unified.jsonl, so shipping them per-incident
// in haul-rules was inflating the satellite repo by ~30% with no consumer
// benefit (TIP/SOAR pipelines using CrowdStrike or Datadog can read the
// unified feed in half the bytes). They remain registered for explicit
// opt-in via `--backends crowdstrike-ioc,datadog,...`.
//
// snort + suricata stay in the default set — they're network IDS formats
// that home/SMB users deploy through pfSense / OPNsense, which is a real
// non-redundant audience the unified feed doesn't serve.
func All(csIOCAction string) []Backend {
	return []Backend{
		kql.New(),
		sentinel.New(),
		splunk.New(),
		elastic.New(),
		wazuh.New(),
		chronicle.New(),
		suricata.New(),
		snort.New(),
		crowdstrike.NewLogScale(),
		qradar.New(),
	}
}

// AllIncludingRedundant returns the full registered set, including the
// pure-IOC backends excluded from the default. Used by ByName so that
// operators who explicitly name a redundant backend still get it.
func AllIncludingRedundant(csIOCAction string) []Backend {
	return append(All(csIOCAction),
		crowdstrike.NewIOC(csIOCAction),
		datadog.New(),
	)
}

// ByName returns only backends whose Name() matches one of the given names.
// It returns an error if any name has no corresponding registered backend.
// The special name "stix" is allowed as a generate-level flag, not a backend.
func ByName(names []string, csIOCAction string) ([]Backend, error) {
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}
	delete(nameSet, "stix") // handled at the generate layer, not a backend
	var out []Backend
	for _, b := range AllIncludingRedundant(csIOCAction) {
		if nameSet[b.Name()] {
			delete(nameSet, b.Name())
			out = append(out, b)
		}
	}
	if len(nameSet) > 0 {
		unknown := make([]string, 0, len(nameSet))
		for n := range nameSet {
			unknown = append(unknown, n)
		}
		return nil, fmt.Errorf("unknown backend(s): %s", strings.Join(unknown, ", "))
	}
	return out, nil
}
