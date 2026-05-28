package actor

import (
	"testing"
)

func TestMergeLinkedIncidents(t *testing.T) {
	fresh := []*ActorProfile{
		{ID: "apt28", Name: "APT28"},
		{ID: "lazarus", Name: "Lazarus Group"},
	}

	diskProfiles := []*ActorProfile{
		{
			ID:   "apt28",
			Name: "APT28",
			LinkedIncidents: []IncidentLink{
				{IncidentID: "supply-2024-001", Module: "supply", MatchType: "inferred", Confidence: 0.65},
				{IncidentID: "cve-2023-002", Module: "cve", MatchType: "explicit", Confidence: 0.90},
			},
			AggregatedIOCs: AggregatedIOCs{
				Domains: []string{"evil.example.com"},
				IPs:     []string{"1.2.3.4"},
				Hashes:  []string{"deadbeef"},
			},
		},
		// lazarus has no disk profile — should be a no-op
	}
	disk := Load(diskProfiles)

	MergeLinkedIncidents(fresh, disk)

	apt28 := fresh[0]
	if len(apt28.LinkedIncidents) != 2 {
		t.Fatalf("apt28: want 2 linked incidents, got %d", len(apt28.LinkedIncidents))
	}
	if apt28.LinkedIncidents[0].IncidentID != "supply-2024-001" {
		t.Errorf("apt28: unexpected first incident %q", apt28.LinkedIncidents[0].IncidentID)
	}
	if len(apt28.AggregatedIOCs.Domains) != 1 || apt28.AggregatedIOCs.Domains[0] != "evil.example.com" {
		t.Errorf("apt28: IOC domains not merged: %v", apt28.AggregatedIOCs.Domains)
	}
	if len(apt28.AggregatedIOCs.IPs) != 1 || apt28.AggregatedIOCs.IPs[0] != "1.2.3.4" {
		t.Errorf("apt28: IOC IPs not merged: %v", apt28.AggregatedIOCs.IPs)
	}

	lazarus := fresh[1]
	if len(lazarus.LinkedIncidents) != 0 {
		t.Errorf("lazarus: expected no incidents (no disk profile), got %d", len(lazarus.LinkedIncidents))
	}
}

func TestMergeLinkedIncidents_Dedup(t *testing.T) {
	// If the fresh profile already has a link (e.g. from this run's attribution),
	// MergeLinkedIncidents must not duplicate it.
	fresh := []*ActorProfile{
		{
			ID:   "apt29",
			Name: "APT29",
			LinkedIncidents: []IncidentLink{
				{IncidentID: "cve-2024-already", Module: "cve", MatchType: "inferred", Confidence: 0.65},
			},
		},
	}
	diskProfiles := []*ActorProfile{
		{
			ID: "apt29",
			LinkedIncidents: []IncidentLink{
				{IncidentID: "cve-2024-already", Module: "cve", MatchType: "inferred", Confidence: 0.65}, // duplicate
				{IncidentID: "supply-2023-old", Module: "supply", MatchType: "explicit", Confidence: 0.90},
			},
		},
	}
	disk := Load(diskProfiles)

	MergeLinkedIncidents(fresh, disk)

	apt29 := fresh[0]
	if len(apt29.LinkedIncidents) != 2 {
		t.Fatalf("apt29: want 2 unique incidents, got %d", len(apt29.LinkedIncidents))
	}
}

func TestMergeLinkedIncidents_NilDisk(t *testing.T) {
	fresh := []*ActorProfile{{ID: "apt28"}}
	MergeLinkedIncidents(fresh, nil) // must not panic
}
