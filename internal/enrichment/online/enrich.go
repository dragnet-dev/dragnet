package online

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/dragnet-dev/dragnet/internal/config"
	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/dragnet-dev/dragnet/internal/state"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs"
)

// Enricher runs online infrastructure enrichment against RIPEstat, Shodan
// InternetDB, and crt.sh. Results are cached in EnrichmentCache to avoid
// re-querying within the configured TTL.
type Enricher struct {
	cfg    config.OnlineEnrichConfig
	cache  *state.EnrichmentCache
	client *http.Client
}

func New(cfg config.OnlineEnrichConfig, cache *state.EnrichmentCache) *Enricher {
	return &Enricher{
		cfg:    cfg,
		cache:  cache,
		client: blogs.NewSafeHTTPClient(30 * time.Second),
	}
}

// EnrichAll processes all incidents across modules, attaching IP and domain
// enrichment metadata in-place. Returns the count of newly enriched IOCs.
func (e *Enricher) EnrichAll(ctx context.Context, allModules map[string][]*incident.Incident) int {
	if !e.cfg.Enabled {
		return 0
	}

	// Collect unique IPs and domains across all incidents.
	uniqueIPs := map[string]bool{}
	uniqueDomains := map[string]bool{}
	for _, incidents := range allModules {
		for _, inc := range incidents {
			for _, ip := range inc.Indicators.IPs {
				uniqueIPs[ip.Value] = true
			}
			for _, d := range inc.Indicators.Domains {
				uniqueDomains[d.Value] = true
			}
		}
	}

	newEnrichments := 0

	if e.cfg.RIPEstat || e.cfg.ShodanInternetDB {
		for ip := range uniqueIPs {
			if e.cache.IPFresh(ip, e.cfg.CacheTTLDays) {
				continue
			}
			enr := incident.IPEnrichment{}
			if e.cfg.RIPEstat {
				enr.ASN, enr.BGPPrefix, enr.Country = enrichIPRIPE(ctx, e.client, ip)
			}
			if e.cfg.ShodanInternetDB {
				enr.Ports, enr.Tags, enr.CVEs = enrichIPInternetDB(ctx, e.client, ip)
			}
			e.cache.SetIP(ip, enr)
			newEnrichments++
			log.Printf("[online-enrich] ip %s: asn=%q ports=%d cves=%d", ip, enr.ASN, len(enr.Ports), len(enr.CVEs))
		}
	}

	if e.cfg.CRTSh {
		maxRelated := e.cfg.CRTShMaxRelated
		if maxRelated <= 0 {
			maxRelated = 20
		}
		for domain := range uniqueDomains {
			if e.cache.DomainFresh(domain, e.cfg.CacheTTLDays) {
				continue
			}
			related, issuers := enrichDomainCRTSh(ctx, e.client, domain, maxRelated)
			enr := incident.DomainEnrichment{
				RelatedDomains: related,
				CertIssuers:    issuers,
			}
			e.cache.SetDomain(domain, enr)
			newEnrichments++
			log.Printf("[online-enrich] domain %s: related=%d issuers=%d", domain, len(related), len(issuers))
		}
	}

	// Attach cached enrichment to every matching IOC in every incident, and
	// expand crt.sh-discovered related domains into the incident's domain list.
	for _, incidents := range allModules {
		for _, inc := range incidents {
			for i, ip := range inc.Indicators.IPs {
				if enr, ok := e.cache.IPs[ip.Value]; ok {
					inc.Indicators.IPs[i].IPEnrich = &enr
				}
			}
			for i, d := range inc.Indicators.Domains {
				if enr, ok := e.cache.Domains[d.Value]; ok {
					inc.Indicators.Domains[i].DomainEnrich = &enr
					// Add newly discovered related domains at low confidence.
					for _, rel := range enr.RelatedDomains {
						if !hasDomain(inc.Indicators.Domains, rel) {
							inc.Indicators.Domains = append(inc.Indicators.Domains, incident.IndicatorValue{
								Value:      rel,
								Sources:    []string{"crt.sh"},
								Confidence: 0.55,
							})
						}
					}
				}
			}
		}
	}

	return newEnrichments
}

func hasDomain(domains []incident.IndicatorValue, value string) bool {
	for _, d := range domains {
		if d.Value == value {
			return true
		}
	}
	return false
}
