// Package cmd: `dragnet scrub` retroactively re-applies the current
// iocutil.Normalize and deconflict filter rules to all historical JSONL shards.
//
// This cleans up bad IOC values that entered haul before the circuit breaker
// was in place, or before the deconflict blocklist was expanded. Run locally
// after updating filter rules and push the resulting diff to haul.
//
// Default is dry-run. Use --apply to write changes.
package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/dragnet-dev/dragnet/internal/iocutil"
	"github.com/spf13/cobra"
)

var scrubCmd = &cobra.Command{
	Use:   "scrub",
	Short: "Re-apply current IOC filter rules to all historical JSONL shards",
	Long: `scrub iterates over every incidents/all/*.jsonl shard and re-applies the
current iocutil.Normalize and deconflict filter rules to every domain, IP, URL,
and file hash. Values that are now blocked (e.g. newly added to the blocklist,
or empty file hashes) are silently removed.

Use this after expanding the deconflict blocklist to retroactively clean
historical shards without a full re-sync.

Default is dry-run. Use --apply to write changes.`,
	SilenceUsage: true,
	RunE:         runScrub,
}

var (
	scrubApply       bool
	scrubRoot        string
	scrubMods        string
	scrubRemoveEmpty bool
)

func init() {
	scrubCmd.Flags().BoolVar(&scrubApply, "apply", false,
		"Write changes. Default is dry-run.")
	scrubCmd.Flags().StringVar(&scrubRoot, "root", "",
		"Root directory containing module subdirs (defaults to config file dir).")
	scrubCmd.Flags().StringVar(&scrubMods, "modules", "supply,malware,ransomware,cve,container",
		"Comma-separated list of modules to scrub.")
	scrubCmd.Flags().BoolVar(&scrubRemoveEmpty, "remove-empty", true,
		"Remove incidents that have no packages and no IOC indicators after scrubbing.")
	rootCmd.AddCommand(scrubCmd)
}

type scrubStats struct {
	removedDomains   int
	removedIPs       int
	removedURLs      int
	removedHashes    int
	removedIncidents int
	rewrittenFiles   int
}

func runScrub(_ *cobra.Command, _ []string) error {
	root := scrubRoot
	if root == "" {
		root = dataDir()
	}
	modules := strings.Split(scrubMods, ",")

	grand := scrubStats{}
	for _, mod := range modules {
		stats, err := scrubModule(root, mod)
		if err != nil {
			log.Printf("[scrub][%s] error: %v", mod, err)
			continue
		}
		grand.removedDomains += stats.removedDomains
		grand.removedIPs += stats.removedIPs
		grand.removedURLs += stats.removedURLs
		grand.removedHashes += stats.removedHashes
		grand.removedIncidents += stats.removedIncidents
		grand.rewrittenFiles += stats.rewrittenFiles
		if stats.removedDomains+stats.removedIPs+stats.removedURLs+stats.removedHashes+stats.removedIncidents > 0 {
			log.Printf("[scrub][%s] domains=-%d  ips=-%d  urls=-%d  hashes=-%d  incidents=-%d  files=%d",
				mod, stats.removedDomains, stats.removedIPs, stats.removedURLs,
				stats.removedHashes, stats.removedIncidents, stats.rewrittenFiles)
		} else {
			log.Printf("[scrub][%s] clean — no changes needed", mod)
		}
	}

	total := grand.removedDomains + grand.removedIPs + grand.removedURLs + grand.removedHashes + grand.removedIncidents
	if total == 0 {
		log.Printf("[scrub] all shards already clean")
		return nil
	}

	log.Printf("[scrub] total: domains=-%d  ips=-%d  urls=-%d  hashes=-%d  incidents=-%d  files=%d",
		grand.removedDomains, grand.removedIPs, grand.removedURLs,
		grand.removedHashes, grand.removedIncidents, grand.rewrittenFiles)

	if !scrubApply {
		log.Printf("[scrub] DRY-RUN — re-run with --apply to write changes.")
	}
	return nil
}

func scrubModule(root, mod string) (scrubStats, error) {
	allDir := filepath.Join(root, mod, "incidents", "all")
	entries, err := os.ReadDir(allDir)
	if err != nil {
		return scrubStats{}, nil // module not present — skip
	}

	var total scrubStats
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		path := filepath.Join(allDir, e.Name())
		stats, changedCount, err := scanShardForScrub(path)
		if err != nil {
			log.Printf("[scrub][%s] scan %s: %v", mod, e.Name(), err)
			continue
		}
		total.removedDomains += stats.removedDomains
		total.removedIPs += stats.removedIPs
		total.removedURLs += stats.removedURLs
		total.removedHashes += stats.removedHashes
		total.removedIncidents += stats.removedIncidents
		if changedCount > 0 {
			total.rewrittenFiles++
			if scrubApply {
				if err := rewriteShardScrub(path); err != nil {
					log.Printf("[scrub][%s] rewrite %s: %v", mod, e.Name(), err)
				}
			}
		}
	}
	return total, nil
}

// scanShardForScrub dry-runs the scrub on one JSONL shard and returns stats
// plus the count of records that would change.
func scanShardForScrub(path string) (stats scrubStats, changedCount int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return scrubStats{}, 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4<<20), 4<<20)
	for sc.Scan() {
		var raw map[string]any
		if json.Unmarshal(sc.Bytes(), &raw) != nil {
			continue
		}

		inds, _ := raw["indicators"].(map[string]any)

		rd, ri, ru, rh, iocsChanged := scrubCountRemovals(inds)
		stats.removedDomains += rd
		stats.removedIPs += ri
		stats.removedURLs += ru
		stats.removedHashes += rh

		if scrubRemoveEmpty && incidentIsEmpty(raw, inds) {
			stats.removedIncidents++
			changedCount++
			continue
		}
		if iocsChanged {
			changedCount++
		}
	}
	return stats, changedCount, sc.Err()
}

// scrubCountRemovals counts how many IOCs in an indicators map would be
// rejected by the current iocutil.Normalize rules.
func scrubCountRemovals(inds map[string]any) (rd, ri, ru, rh int, changed bool) {
	if inds == nil {
		return
	}
	for _, v := range iocList(inds, "domains") {
		if _, ok := iocutil.Normalize("domain", v); !ok {
			rd++
			changed = true
		}
	}
	for _, v := range iocList(inds, "ips") {
		if _, ok := iocutil.Normalize("ip", v); !ok {
			ri++
			changed = true
		}
	}
	for _, v := range iocList(inds, "urls") {
		if _, ok := iocutil.Normalize("url", v); !ok {
			ru++
			changed = true
		}
	}
	hashes, _ := inds["file_hashes"].([]any)
	for _, item := range hashes {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		algo, _ := m["algorithm"].(string)
		val, _ := m["value"].(string)
		if _, ok := iocutil.Normalize(algo, val); !ok {
			rh++
			changed = true
		}
	}
	return
}

// incidentIsEmpty returns true when the incident will have no meaningful signal
// left after scrubbing: no packages AND every IOC fails Normalize.
func incidentIsEmpty(raw map[string]any, inds map[string]any) bool {
	pkgs, _ := raw["packages"].([]any)
	if len(pkgs) > 0 {
		return false
	}
	if inds == nil {
		return true
	}
	typMap := map[string]string{"domains": "domain", "ips": "ip", "urls": "url"}
	for field, typ := range typMap {
		for _, v := range iocList(inds, field) {
			if _, ok := iocutil.Normalize(typ, v); ok {
				return false
			}
		}
	}
	hashes, _ := inds["file_hashes"].([]any)
	for _, item := range hashes {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		algo, _ := m["algorithm"].(string)
		val, _ := m["value"].(string)
		if _, ok := iocutil.Normalize(algo, val); ok {
			return false
		}
	}
	return true
}

func rewriteShardScrub(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := path + ".scrub.tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}

	bw := bufio.NewWriterSize(out, 1<<20)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 4<<20), 4<<20)

	for sc.Scan() {
		var raw map[string]any
		if json.Unmarshal(sc.Bytes(), &raw) != nil {
			fmt.Fprintln(bw, sc.Text())
			continue
		}

		inds, _ := raw["indicators"].(map[string]any)

		if scrubRemoveEmpty && incidentIsEmpty(raw, inds) {
			continue // drop the incident
		}

		if inds == nil {
			fmt.Fprintln(bw, sc.Text())
			continue
		}

		if applyNormalizeScrub(inds) {
			raw["indicators"] = inds
			b, err := json.Marshal(raw)
			if err != nil {
				fmt.Fprintln(bw, sc.Text())
				continue
			}
			bw.Write(b)
			bw.WriteByte('\n')
		} else {
			fmt.Fprintln(bw, sc.Text())
		}
	}

	if err := sc.Err(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := bw.Flush(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	out.Close()
	return os.Rename(tmp, path)
}

// applyNormalizeScrub mutates the indicators map in-place, removing IOC
// values that iocutil.Normalize rejects. Returns true if anything changed.
func applyNormalizeScrub(inds map[string]any) bool {
	changed := false

	doms, _ := inds["domains"].([]any)
	var cleanDoms []any
	for _, item := range doms {
		m, ok := item.(map[string]any)
		if !ok {
			cleanDoms = append(cleanDoms, item)
			continue
		}
		if _, ok := iocutil.Normalize("domain", fmt.Sprint(m["value"])); ok {
			cleanDoms = append(cleanDoms, item)
		} else {
			changed = true
		}
	}
	if changed {
		inds["domains"] = cleanDoms
	}

	ips, _ := inds["ips"].([]any)
	var cleanIPs []any
	ipChanged := false
	for _, item := range ips {
		m, ok := item.(map[string]any)
		if !ok {
			cleanIPs = append(cleanIPs, item)
			continue
		}
		if _, ok := iocutil.Normalize("ip", fmt.Sprint(m["value"])); ok {
			cleanIPs = append(cleanIPs, item)
		} else {
			ipChanged = true
		}
	}
	if ipChanged {
		inds["ips"] = cleanIPs
		changed = true
	}

	urls, _ := inds["urls"].([]any)
	var cleanURLs []any
	urlChanged := false
	for _, item := range urls {
		m, ok := item.(map[string]any)
		if !ok {
			cleanURLs = append(cleanURLs, item)
			continue
		}
		if _, ok := iocutil.Normalize("url", fmt.Sprint(m["value"])); ok {
			cleanURLs = append(cleanURLs, item)
		} else {
			urlChanged = true
		}
	}
	if urlChanged {
		inds["urls"] = cleanURLs
		changed = true
	}

	hashes, _ := inds["file_hashes"].([]any)
	var cleanHashes []any
	hashChanged := false
	for _, item := range hashes {
		m, ok := item.(map[string]any)
		if !ok {
			cleanHashes = append(cleanHashes, item)
			continue
		}
		algo, _ := m["algorithm"].(string)
		val, _ := m["value"].(string)
		if _, ok := iocutil.Normalize(algo, val); ok {
			cleanHashes = append(cleanHashes, item)
		} else {
			hashChanged = true
		}
	}
	if hashChanged {
		inds["file_hashes"] = cleanHashes
		changed = true
	}

	return changed
}
