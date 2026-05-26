package online

import (
	"context"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dragnet-dev/dragnet/internal/config"
	"github.com/dragnet-dev/dragnet/internal/incident"
	"github.com/dragnet-dev/dragnet/internal/state"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs"
)

const (
	maxWorkers   = 8
	saveInterval = 100
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
// enrichment metadata in-place using up to 8 concurrent workers per IOC type.
// When ctx is cancelled, no new work is dispatched; in-flight workers finish
// gracefully before returning. Returns the count of newly enriched IOCs.
func (e *Enricher) EnrichAll(ctx context.Context, allModules map[string][]*incident.Incident) int {
	return e.EnrichAllWithSave(ctx, allModules, nil)
}

// EnrichAllWithSave is like EnrichAll but calls saveFn (if non-nil) after
// every saveInterval new enrichments, so partial progress survives a timeout.
func (e *Enricher) EnrichAllWithSave(ctx context.Context, allModules map[string][]*incident.Incident, saveFn func()) int {
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

	var total atomic.Int64

	// maybePeriodicSave triggers saveFn every saveInterval completions.
	maybePeriodicSave := func(n int64) {
		if saveFn == nil {
			return
		}
		if n%saveInterval == 0 {
			saveFn()
		}
	}

	// --- IP enrichment ---
	if e.cfg.RIPEstat || e.cfg.ShodanInternetDB {
		staleIPs := make([]string, 0, len(uniqueIPs))
		for ip := range uniqueIPs {
			if !e.cache.IPFresh(ip, e.cfg.CacheTTLDays) {
				staleIPs = append(staleIPs, ip)
			}
		}

		sem := make(chan struct{}, maxWorkers)
		var wg sync.WaitGroup

		for _, ip := range staleIPs {
			// Stop dispatching new work if context is done.
			select {
			case <-ctx.Done():
				goto ipsDone
			default:
			}

			ip := ip
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()

				enr := incident.IPEnrichment{}
				if e.cfg.RIPEstat {
					enr.ASN, enr.BGPPrefix, enr.Country = enrichIPRIPE(ctx, e.client, ip)
				}
				if e.cfg.ShodanInternetDB {
					enr.Ports, enr.Tags, enr.CVEs = enrichIPInternetDB(ctx, e.client, ip)
				}
				e.cache.SetIP(ip, enr)
				n := total.Add(1)
				log.Printf("[online-enrich] ip %s: asn=%q ports=%d cves=%d", ip, enr.ASN, len(enr.Ports), len(enr.CVEs))
				maybePeriodicSave(n)
			}()
		}
	ipsDone:
		wg.Wait()
	}

	// --- Domain enrichment ---
	if e.cfg.CRTSh {
		maxRelated := e.cfg.CRTShMaxRelated
		if maxRelated <= 0 {
			maxRelated = 20
		}

		staleDomains := make([]string, 0, len(uniqueDomains))
		for domain := range uniqueDomains {
			if !e.cache.DomainFresh(domain, e.cfg.CacheTTLDays) {
				staleDomains = append(staleDomains, domain)
			}
		}

		sem := make(chan struct{}, maxWorkers)
		var wg sync.WaitGroup

		for _, domain := range staleDomains {
			select {
			case <-ctx.Done():
				goto domainsDone
			default:
			}

			domain := domain
			mr := maxRelated
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()

				related, issuers := enrichDomainCRTSh(ctx, e.client, domain, mr)
				enr := incident.DomainEnrichment{
					RelatedDomains: related,
					CertIssuers:    issuers,
				}
				e.cache.SetDomain(domain, enr)
				n := total.Add(1)
				log.Printf("[online-enrich] domain %s: related=%d issuers=%d", domain, len(related), len(issuers))
				maybePeriodicSave(n)
			}()
		}
	domainsDone:
		wg.Wait()
	}

	// Final save for any remainder not yet flushed by the periodic trigger.
	if saveFn != nil && total.Load() > 0 && total.Load()%saveInterval != 0 {
		saveFn()
	}

	// Attach cached enrichment to every matching IOC in every incident, and
	// expand crt.sh-discovered related domains into the incident's domain list.
	for _, incidents := range allModules {
		for _, inc := range incidents {
			for i, ip := range inc.Indicators.IPs {
				if enr, ok := e.cache.GetIP(ip.Value); ok {
					inc.Indicators.IPs[i].IPEnrich = &enr
				}
			}
			for i, d := range inc.Indicators.Domains {
				if enr, ok := e.cache.GetDomain(d.Value); ok {
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

	return int(total.Load())
}

func hasDomain(domains []incident.IndicatorValue, value string) bool {
	for _, d := range domains {
		if d.Value == value {
			return true
		}
	}
	return false
}
