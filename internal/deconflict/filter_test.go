package deconflict

import "testing"

func TestDomainBlocksCommonFeedNoise(t *testing.T) {
	for _, domain := range []string{
		"config.json",
		"defunct.dat",
		"old.evil.example",
		"raw.githubusercontent",
		"drive.google.com",
		"bitbucket.org",
		"ranked-accordingly-ab-hired.trycloudflare",
		"1a820b09-95ba-44eb-b350-417e8241b725-00-1lgwuuen9b77p.worf",
		"rdhrse.qpon",
		"gov.incometax",
		"eth.blockscout.com",
	} {
		if !Domain(domain) {
			t.Fatalf("Domain(%q) = false, want true", domain)
		}
	}
}

func TestDomainAllowsLikelyMaliciousDomains(t *testing.T) {
	for _, domain := range []string{
		"evil.example.net",
		"0x666.info",
		"newenewmew.duckdns.org",
		"fd.v2downf.shop",
	} {
		if Domain(domain) {
			t.Fatalf("Domain(%q) = true, want false", domain)
		}
	}
}
