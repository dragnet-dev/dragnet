package multidomain

import (
	"github.com/dragnet-dev/dragnet/internal/sources/multidomain/bleepingcomputer"
	"github.com/dragnet-dev/dragnet/internal/sources/multidomain/crowdstrike"
	"github.com/dragnet-dev/dragnet/internal/sources/multidomain/jfrog"
	"github.com/dragnet-dev/dragnet/internal/sources/multidomain/krebsonsecurity"
	"github.com/dragnet-dev/dragnet/internal/sources/multidomain/mandiant"
	"github.com/dragnet-dev/dragnet/internal/sources/multidomain/microsoft_sec"
	"github.com/dragnet-dev/dragnet/internal/sources/multidomain/protectai"
	"github.com/dragnet-dev/dragnet/internal/sources/multidomain/securelist"
	"github.com/dragnet-dev/dragnet/internal/sources/multidomain/sentinelone"
	"github.com/dragnet-dev/dragnet/internal/sources/multidomain/the_hacker_news"
	"github.com/dragnet-dev/dragnet/internal/sources/multidomain/unit42"
)

// AllFetchers returns one instance of every registered multi-domain fetcher.
func AllFetchers() []MultiDomainFetcher {
	return []MultiDomainFetcher{
		bleepingcomputer.New(),
		the_hacker_news.New(),
		krebsonsecurity.New(),
		mandiant.New(),
		unit42.New(),
		microsoft_sec.New(),
		securelist.New(),
		crowdstrike.New(),
		sentinelone.New(),
		jfrog.New(),
		protectai.New(),
	}
}

// GetFetcher returns the fetcher with the given name, or nil if not found.
func GetFetcher(name string) MultiDomainFetcher {
	for _, f := range AllFetchers() {
		if f.Name() == name {
			return f
		}
	}
	return nil
}
