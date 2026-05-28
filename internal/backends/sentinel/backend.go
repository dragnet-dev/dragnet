package sentinel

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dragnet-dev/dragnet/internal/backends/kql"
	"github.com/dragnet-dev/dragnet/internal/backends/sigma"
)

// Backend produces Sentinel-native YAML (ARM-compatible, GitHub connector ready).
type Backend struct{}

func New() *Backend { return &Backend{} }

func (b *Backend) Name() string            { return "sentinel" }
func (b *Backend) OutputExtension() string { return ".yaml" }

func (b *Backend) Compile(sigmaYAML []byte) ([]byte, error) {
	// 1. Parse just enough of the Sigma rule to build the wrapper.
	var rawDoc map[string]interface{}
	if err := yaml.Unmarshal(sigmaYAML, &rawDoc); err != nil {
		return nil, fmt.Errorf("sentinel: parse sigma: %w", err)
	}

	rule := extractMeta(rawDoc)

	// 2. Get the KQL query from the KQL backend.
	kqlBackend := kql.New()
	kqlBytes, err := kqlBackend.Compile(sigmaYAML)
	if err != nil {
		return nil, fmt.Errorf("sentinel: kql compile: %w", err)
	}

	// 3. Map logsource.category to Sentinel data types and connectors.
	dataTypes, connectorID := categoryToConnector(rule.category)

	// 4. Map level to Sentinel severity.
	severity := levelToSeverity(rule.level)

	// 5. Map tags to tactics and techniques.
	tactics, techniques := tagsToMITRE(rule.tags)

	// 6. Build the Sentinel YAML.
	out, err := buildSentinelYAML(rule, string(kqlBytes), connectorID, dataTypes, severity, tactics, techniques)
	if err != nil {
		return nil, fmt.Errorf("sentinel: marshal: %w", err)
	}
	return out, nil
}

// ---- meta extraction ----

type ruleMeta struct {
	id          string
	name        string
	description string
	level       string
	category    string
	tags        []string
}

func extractMeta(doc map[string]interface{}) ruleMeta {
	r := ruleMeta{}
	r.id, _ = doc["id"].(string)
	r.name, _ = doc["title"].(string)
	r.description, _ = doc["description"].(string)
	r.level, _ = doc["level"].(string)
	r.tags = sigma.ToStringSlice(doc["tags"])

	if ls, ok := doc["logsource"].(map[string]interface{}); ok {
		r.category, _ = ls["category"].(string)
	}
	return r
}

// ---- mapping helpers ----

var categoryConnectorMap = map[string]struct {
	dataType  string
	connector string
}{
	"network_connection": {"DeviceNetworkEvents", "MicrosoftDefenderAdvancedThreatProtection"},
	"dns_query":          {"DeviceNetworkEvents", "MicrosoftDefenderAdvancedThreatProtection"},
	"file_event":         {"DeviceFileEvents", "MicrosoftDefenderAdvancedThreatProtection"},
	"process_creation":   {"DeviceProcessEvents", "MicrosoftDefenderAdvancedThreatProtection"},
	"process_access":     {"DeviceEvents", "MicrosoftDefenderAdvancedThreatProtection"},
	"registry_event":     {"DeviceRegistryEvents", "MicrosoftDefenderAdvancedThreatProtection"},
}

func categoryToConnector(category string) (dataTypes []string, connectorID string) {
	if entry, ok := categoryConnectorMap[category]; ok {
		return []string{entry.dataType}, entry.connector
	}
	return []string{"SecurityEvent"}, "SecurityEvents"
}

var levelSeverityMap = map[string]string{
	"critical": "High",
	"high":     "High",
	"medium":   "Medium",
	"low":      "Low",
	"":         "Informational",
}

func levelToSeverity(level string) string {
	if s, ok := levelSeverityMap[strings.ToLower(level)]; ok {
		return s
	}
	return "Informational"
}

// tacticMap maps MITRE technique IDs (lower-case) to Sentinel tactic names.
var tacticMap = map[string]string{
	"t1195": "InitialAccess",
	"t1552": "CredentialAccess",
	"t1041": "Exfiltration",
	"t1543": "Persistence",
	"t1070": "DefenseEvasion",
	"t1057": "Discovery",
}

func tagsToMITRE(tags []string) (tactics []string, techniques []string) {
	tacticSet := map[string]bool{}
	for _, tag := range tags {
		tag = strings.ToLower(tag)
		// Sigma tags look like "attack.t1041" or "attack.exfiltration"
		if strings.HasPrefix(tag, "attack.") {
			part := strings.TrimPrefix(tag, "attack.")
			if strings.HasPrefix(part, "t") {
				// Technique ID
				tid := strings.ToUpper(part) // e.g. T1041
				techniques = append(techniques, tid)
				if tactic, ok := tacticMap[strings.ToLower(part)]; ok {
					if !tacticSet[tactic] {
						tacticSet[tactic] = true
						tactics = append(tactics, tactic)
					}
				}
			}
		}
	}
	return tactics, techniques
}

// ---- YAML output ----

type dataConnector struct {
	ConnectorID string   `yaml:"connectorId"`
	DataTypes   []string `yaml:"dataTypes"`
}

// buildSentinelYAML constructs the Sentinel analytic rule YAML using yaml.Node
// so we can force literal block style (|) for the query field.
func buildSentinelYAML(
	rule ruleMeta,
	kqlQuery string,
	connectorID string,
	dataTypes []string,
	severity string,
	tactics []string,
	techniques []string,
) ([]byte, error) {
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}

	addStr := func(key, val string) {
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: val},
		)
	}

	addLiteral := func(key, val string) {
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: val, Style: yaml.LiteralStyle},
		)
	}

	addStrList := func(key string, vals []string) {
		if len(vals) == 0 {
			return
		}
		listNode := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, v := range vals {
			listNode.Content = append(listNode.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v},
			)
		}
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
			listNode,
		)
	}

	addStr("id", rule.id)
	addStr("name", rule.name)
	addLiteral("description", rule.description)
	addStr("severity", severity)
	addStr("status", "Available")

	// requiredDataConnectors
	connNode := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	connItem := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	connItem.Content = append(connItem.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "connectorId"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: connectorID},
	)
	dtSeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, dt := range dataTypes {
		dtSeq.Content = append(dtSeq.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: dt},
		)
	}
	connItem.Content = append(connItem.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "dataTypes"},
		dtSeq,
	)
	connNode.Content = append(connNode.Content, connItem)
	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "requiredDataConnectors"},
		connNode,
	)

	addStrList("tactics", tactics)
	addStrList("relevantTechniques", techniques)
	addLiteral("query", kqlQuery)

	doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return out, nil
}

