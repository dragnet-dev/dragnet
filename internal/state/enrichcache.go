package state

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/dragnet-dev/dragnet/internal/incident"
)

// EnrichmentCache persists online IOC enrichment results so each unique IP or
// domain is queried at most once per TTL period across workflow runs.
// All exported methods are safe for concurrent use.
type EnrichmentCache struct {
	mu        sync.Mutex
	IPs       map[string]incident.IPEnrichment     `json:"ips"`
	Domains   map[string]incident.DomainEnrichment `json:"domains"`
	IPsAt     map[string]time.Time                 `json:"ips_at"`
	DomainsAt map[string]time.Time                 `json:"domains_at"`
}

func NewEnrichmentCache() *EnrichmentCache {
	return &EnrichmentCache{
		IPs:       make(map[string]incident.IPEnrichment),
		Domains:   make(map[string]incident.DomainEnrichment),
		IPsAt:     make(map[string]time.Time),
		DomainsAt: make(map[string]time.Time),
	}
}

func LoadEnrichmentCache(path string) (*EnrichmentCache, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return NewEnrichmentCache(), nil
	}
	if err != nil {
		return nil, err
	}
	c := NewEnrichmentCache()
	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}
	return c, nil
}

func SaveEnrichmentCache(path string, c *EnrichmentCache) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// IPFresh returns true when the IP was cached within ttlDays.
func (c *EnrichmentCache) IPFresh(ip string, ttlDays int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.IPsAt[ip]
	return ok && time.Since(t) < time.Duration(ttlDays)*24*time.Hour
}

// DomainFresh returns true when the domain was cached within ttlDays.
func (c *EnrichmentCache) DomainFresh(domain string, ttlDays int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.DomainsAt[domain]
	return ok && time.Since(t) < time.Duration(ttlDays)*24*time.Hour
}

// SetIP stores enrichment data for an IP and marks the timestamp.
func (c *EnrichmentCache) SetIP(ip string, enr incident.IPEnrichment) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.IPs[ip] = enr
	c.IPsAt[ip] = time.Now()
}

// SetDomain stores enrichment data for a domain and marks the timestamp.
func (c *EnrichmentCache) SetDomain(domain string, enr incident.DomainEnrichment) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Domains[domain] = enr
	c.DomainsAt[domain] = time.Now()
}

// GetIP returns the cached enrichment for ip and whether it was present.
func (c *EnrichmentCache) GetIP(ip string) (incident.IPEnrichment, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	enr, ok := c.IPs[ip]
	return enr, ok
}

// GetDomain returns the cached enrichment for domain and whether it was present.
func (c *EnrichmentCache) GetDomain(domain string) (incident.DomainEnrichment, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	enr, ok := c.Domains[domain]
	return enr, ok
}
