package stix

// BuildCombinedBundle merges all per-incident bundles into a single bundle.
// Objects are deduplicated by STIX ID so shared objects (same threat actor
// across multiple incidents) appear only once.
func BuildCombinedBundle(bundles []Bundle) Bundle {
	seen := map[string]bool{}
	objects := []any{}

	for _, b := range bundles {
		for _, obj := range b.Objects {
			id := objectID(obj)
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			objects = append(objects, obj)
		}
	}

	return Bundle{
		Type:    "bundle",
		ID:      StixID("bundle", "dragnet:all"),
		Objects: objects,
	}
}

// objectID extracts the STIX ID from any STIX object using a type switch.
func objectID(obj any) string {
	switch v := obj.(type) {
	case Identity:
		return v.ID
	case Indicator:
		return v.ID
	case Malware:
		return v.ID
	case ThreatActor:
		return v.ID
	case Campaign:
		return v.ID
	case AttackPattern:
		return v.ID
	case Vulnerability:
		return v.ID
	case Relationship:
		return v.ID
	}
	return ""
}
