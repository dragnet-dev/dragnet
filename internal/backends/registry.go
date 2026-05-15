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

// All returns one instance of every registered backend.
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
		crowdstrike.NewIOC(csIOCAction),
		qradar.New(),
		datadog.New(),
	}
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
	for _, b := range All(csIOCAction) {
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
