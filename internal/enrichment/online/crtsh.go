package online

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const crtshBase = "https://crt.sh"

type crtshEntry struct {
	NameValue string `json:"name_value"`
	IssuerCN  string `json:"issuer_cn"`
}

// enrichDomainCRTSh fetches related domains (cert SANs) and cert issuers for
// domain from crt.sh. Returns nil slices on any error.
// maxRelated caps the number of related domains to avoid wildcard cert noise.
func enrichDomainCRTSh(ctx context.Context, client *http.Client, domain string, maxRelated int) (related, issuers []string) {
	defer func() { time.Sleep(250 * time.Millisecond) }()

	url := fmt.Sprintf("%s/?q=%s&output=json", crtshBase, domain)
	body, err := getJSON(ctx, client, url)
	if err != nil {
		return nil, nil
	}
	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, nil
	}

	seenDomains := map[string]bool{domain: true}
	seenIssuers := map[string]bool{}

	for _, e := range entries {
		// name_value may contain newline-separated SANs
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" || strings.HasPrefix(name, "*.") || seenDomains[name] {
				continue
			}
			seenDomains[name] = true
			related = append(related, name)
			if len(related) >= maxRelated {
				goto doneRelated
			}
		}
		if issuer := strings.TrimSpace(e.IssuerCN); issuer != "" && !seenIssuers[issuer] {
			seenIssuers[issuer] = true
			issuers = append(issuers, issuer)
		}
	}
doneRelated:
	// collect remaining issuers after breaking out of related loop
	for _, e := range entries {
		if issuer := strings.TrimSpace(e.IssuerCN); issuer != "" && !seenIssuers[issuer] {
			seenIssuers[issuer] = true
			issuers = append(issuers, issuer)
		}
	}

	return related, issuers
}
