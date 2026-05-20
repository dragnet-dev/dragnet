package cmd

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/dragnet-dev/dragnet/internal/sources"
	"github.com/dragnet-dev/dragnet/internal/sources/blogs"
	"github.com/spf13/cobra"
)

var probeBlogsCmd = &cobra.Command{
	Use:   "probe-blogs",
	Short: "Live-test every blog parser against its RSS feed and report IOC extraction health",
	Long: `probe-blogs fetches the most recent articles from each registered blog source,
runs the full parser pipeline (MatchesPost → fetch HTML → ParseIOCs), and
prints a table showing how many IOCs each parser extracted.

Useful for detecting parsers that have silently broken due to blog HTML
restructuring, dead feeds, or keyword drift.

Exit codes:
  0  all parsers are healthy (matched ≥1 article and extracted ≥1 IOC, or no matching articles)
  1  one or more parsers returned feed-err or no-iocs`,
	SilenceUsage: true,
	RunE:         runProbeBlogs,
}

var (
	probeBlogsArticles  int
	probeBlogsSource    string
	probeBlogsConcurrent int
	probeBlogsTimeout   int
)

func init() {
	probeBlogsCmd.Flags().IntVar(&probeBlogsArticles, "articles", 5,
		"Number of recent articles to check per feed")
	probeBlogsCmd.Flags().StringVar(&probeBlogsSource, "source", "",
		"Probe only this source by name (default: all)")
	probeBlogsCmd.Flags().IntVar(&probeBlogsConcurrent, "concurrency", 5,
		"Maximum concurrent feed fetches")
	probeBlogsCmd.Flags().IntVar(&probeBlogsTimeout, "timeout", 60,
		"Per-feed timeout in seconds")
}

func runProbeBlogs(_ *cobra.Command, _ []string) error {
	clients := sources.AllBlogClients()

	if probeBlogsSource != "" {
		var filtered []*blogs.Client
		for _, c := range clients {
			if c.Name() == probeBlogsSource {
				filtered = append(filtered, c)
				break
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("no blog source named %q", probeBlogsSource)
		}
		clients = filtered
	}

	results := make([]blogs.ProbeResult, len(clients))
	sem := make(chan struct{}, probeBlogsConcurrent)
	var wg sync.WaitGroup

	for i, c := range clients {
		wg.Add(1)
		go func(idx int, client *blogs.Client) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(),
				time.Duration(probeBlogsTimeout)*time.Second)
			defer cancel()
			results[idx] = client.Probe(ctx, probeBlogsArticles)
		}(i, c)
	}
	wg.Wait()

	// Sort by status severity so broken parsers surface first.
	sort.Slice(results, func(i, j int) bool {
		return statusOrder(results[i].Status()) < statusOrder(results[j].Status())
	})

	printProbeTable(results)

	// Exit non-zero if any parser is definitively broken.
	for _, r := range results {
		if r.Status() == "feed-err" || r.Status() == "no-iocs" {
			return fmt.Errorf("one or more parsers are unhealthy (see table above)")
		}
	}
	return nil
}

func printProbeTable(results []blogs.ProbeResult) {
	const colFmt = "%-20s %-10s %-8s %-8s %-5s %-7s %-7s %-10s\n"
	fmt.Printf(colFmt, "PARSER", "STATUS", "ARTICLES", "MATCHED", "IPs", "DOMAINS", "HASHES", "OTHER")
	fmt.Printf(colFmt,
		"--------------------", "----------", "--------", "--------",
		"-----", "-------", "-------", "----------")

	for _, r := range results {
		ips := r.IOCs["ip"]
		domains := r.IOCs["domain"]
		hashes := r.IOCs["sha256"] + r.IOCs["sha1"] + r.IOCs["md5"]
		other := 0
		for k, v := range r.IOCs {
			if k != "ip" && k != "domain" && k != "sha256" && k != "sha1" && k != "md5" {
				other += v
			}
		}

		status := r.Status()
		if r.FeedErr != "" {
			fmt.Printf(colFmt, r.Name, status, "-", "-", "-", "-", "-", "-")
			fmt.Printf("  feed error: %s\n", r.FeedErr)
			continue
		}
		fmt.Printf(colFmt, r.Name, status,
			fmt.Sprintf("%d", r.Articles),
			fmt.Sprintf("%d", r.Matched),
			fmt.Sprintf("%d", ips),
			fmt.Sprintf("%d", domains),
			fmt.Sprintf("%d", hashes),
			fmt.Sprintf("%d", other),
		)
		if r.ParseErr != "" {
			fmt.Printf("  parse error: %s\n", r.ParseErr)
		}
	}
}

func statusOrder(s string) int {
	switch s {
	case "feed-err":
		return 0
	case "no-iocs":
		return 1
	case "no-match":
		return 2
	case "ok":
		return 3
	}
	return 4
}
