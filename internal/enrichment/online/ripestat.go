package online

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const ripestatBase = "https://stat.ripe.net/data"

// ripestatPrefixResp is the relevant subset of the prefix-overview response.
type ripestatPrefixResp struct {
	Data struct {
		Resource string `json:"resource"`
		ASNs     []struct {
			ASN    int    `json:"asn"`
			Holder string `json:"holder"`
		} `json:"asns"`
	} `json:"data"`
}

// ripestatGeoResp is the relevant subset of the rir-geo response.
type ripestatGeoResp struct {
	Data struct {
		Located []struct {
			Country string `json:"country"`
		} `json:"located"`
	} `json:"data"`
}

// enrichIPRIPE fetches ASN, BGP prefix, and country for ip from RIPEstat.
// Returns empty strings on any error (non-fatal — data is best-effort).
func enrichIPRIPE(ctx context.Context, client *http.Client, ip string) (asn, bgpPrefix, country string) {
	asn, bgpPrefix = fetchRIPEPrefix(ctx, client, ip)
	time.Sleep(200 * time.Millisecond)
	country = fetchRIPECountry(ctx, client, ip)
	time.Sleep(200 * time.Millisecond)
	return asn, bgpPrefix, country
}

func fetchRIPEPrefix(ctx context.Context, client *http.Client, ip string) (asn, bgpPrefix string) {
	url := fmt.Sprintf("%s/prefix-overview/data.json?resource=%s", ripestatBase, ip)
	body, err := getJSON(ctx, client, url)
	if err != nil {
		return "", ""
	}
	var resp ripestatPrefixResp
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.Data.ASNs) == 0 {
		return "", ""
	}
	a := resp.Data.ASNs[0]
	bgpPrefix = resp.Data.Resource
	if a.Holder != "" {
		asn = fmt.Sprintf("AS%d %s", a.ASN, a.Holder)
	} else {
		asn = fmt.Sprintf("AS%d", a.ASN)
	}
	return asn, bgpPrefix
}

func fetchRIPECountry(ctx context.Context, client *http.Client, ip string) string {
	url := fmt.Sprintf("%s/rir-geo/data.json?resource=%s", ripestatBase, ip)
	body, err := getJSON(ctx, client, url)
	if err != nil {
		return ""
	}
	var resp ripestatGeoResp
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.Data.Located) == 0 {
		return ""
	}
	return resp.Data.Located[0].Country
}

func getJSON(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Dragnet-CTI-Bot/1.0 (+https://github.com/dragnet-dev/dragnet)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("404: %s", url)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
