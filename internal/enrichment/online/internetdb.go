package online

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const internetDBBase = "https://internetdb.shodan.io"

type internetDBResp struct {
	Ports []int    `json:"ports"`
	Tags  []string `json:"tags"`
	Vulns []string `json:"vulns"`
}

// enrichIPInternetDB fetches open ports, Shodan tags, and known CVEs for ip.
// Returns zero-value slices on 404 or any error.
func enrichIPInternetDB(ctx context.Context, client *http.Client, ip string) (ports []int, tags, cves []string) {
	defer func() { time.Sleep(time.Second) }()

	url := fmt.Sprintf("%s/%s", internetDBBase, ip)
	body, err := getJSON(ctx, client, url)
	if err != nil {
		return nil, nil, nil
	}
	var resp internetDBResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, nil
	}
	return resp.Ports, resp.Tags, resp.Vulns
}
