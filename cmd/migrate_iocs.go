// Package cmd: `dragnet migrate-iocs` retroactively fixes IOC quality issues
// in existing incident JSONL shards.
//
// Problems addressed:
//  1. IPs stored under domains[] (from defanged-IP patterns mis-typed as domain)
//  2. Trailing dots on domain/IP values (sentence-ending period captured by regex)
//  3. Private/loopback IPs in ips[] (RFC1918, link-local, loopback)
//
// Default is dry-run. Use --apply to write changes.
package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var migrateIOCsCmd = &cobra.Command{
	Use:          "migrate-iocs",
	Short:        "Fix IOC quality issues (IP-as-domain, trailing dots, private IPs) in existing shards",
	SilenceUsage: true,
	RunE:         runMigrateIOCs,
}

var (
	migrateIOCsApply bool
	migrateIOCsRoot  string
	migrateIOCsMods  string
)

func init() {
	migrateIOCsCmd.Flags().BoolVar(&migrateIOCsApply, "apply", false,
		"Write changes. Default is dry-run.")
	migrateIOCsCmd.Flags().StringVar(&migrateIOCsRoot, "root", "",
		"Root directory containing module subdirs (defaults to config file dir).")
	migrateIOCsCmd.Flags().StringVar(&migrateIOCsMods, "modules", "malware,cve,ransomware,supply",
		"Comma-separated list of modules to migrate.")
	rootCmd.AddCommand(migrateIOCsCmd)
}

var (
	reIPv4         = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	privateBlocked = func() []*net.IPNet {
		var nets []*net.IPNet
		for _, cidr := range []string{
			"127.0.0.0/8", "169.254.0.0/16",
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
			"::1/128", "fc00::/7", "fe80::/10",
		} {
			_, n, _ := net.ParseCIDR(cidr)
			if n != nil {
				nets = append(nets, n)
			}
		}
		return nets
	}()
	publicDNS = map[string]bool{
		"8.8.8.8": true, "8.8.4.4": true,
		"1.1.1.1": true, "1.0.0.1": true,
		"9.9.9.9": true,
	}
)

func isPrivateIP(s string) bool {
	parsed := net.ParseIP(s)
	if parsed == nil {
		return false
	}
	if publicDNS[s] {
		return true
	}
	for _, cidr := range privateBlocked {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// defaultAttackType maps module names to the attack_type to fill in when the
// field is missing on existing incidents.
var defaultAttackType = map[string]string{
	"supply":     "malicious_publish",
	"malware":    "malware",
	"ransomware": "ransomware",
	"cve":        "vulnerability",
	"container":  "vulnerability",
}

type iocFix struct {
	incidentID string
	kind       string
	detail     string
}

func runMigrateIOCs(_ *cobra.Command, _ []string) error {
	root := migrateIOCsRoot
	if root == "" {
		root = dataDir()
	}
	modules := strings.Split(migrateIOCsMods, ",")

	var allFixes []iocFix
	type fileWithMod struct {
		path string
		mod  string
	}
	var affectedFiles []fileWithMod

	for _, mod := range modules {
		allDir := filepath.Join(root, mod, "incidents", "all")
		entries, err := os.ReadDir(allDir)
		if err != nil {
			log.Printf("[migrate-iocs][%s] read dir: %v (skipping)", mod, err)
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
				continue
			}
			path := filepath.Join(allDir, e.Name())
			fixes, err := scanShardForIOCIssues(path, mod)
			if err != nil {
				log.Printf("[migrate-iocs][%s] scan %s: %v", mod, e.Name(), err)
				continue
			}
			if len(fixes) > 0 {
				allFixes = append(allFixes, fixes...)
				affectedFiles = append(affectedFiles, fileWithMod{path, mod})
			}
		}
	}

	if len(allFixes) == 0 {
		log.Printf("[migrate-iocs] no issues found — already clean")
		return nil
	}

	// Summarise by kind
	counts := map[string]int{}
	for _, f := range allFixes {
		counts[f.kind]++
	}
	log.Printf("[migrate-iocs] found %d issue(s) across %d file(s):", len(allFixes), len(affectedFiles))
	for k, n := range counts {
		log.Printf("  %s: %d", k, n)
	}
	// Only log individual entries for IOC issues (not metadata backfills which are too verbose).
	for _, f := range allFixes {
		if f.kind != "empty-attack-type" {
			log.Printf("  [%s] %s — %s", f.kind, f.incidentID, f.detail)
		}
	}

	if !migrateIOCsApply {
		log.Printf("[migrate-iocs] DRY-RUN — re-run with --apply to fix them.")
		return nil
	}

	total := 0
	for _, fm := range affectedFiles {
		n, err := rewriteShardFixIOCs(fm.path, fm.mod)
		if err != nil {
			log.Printf("[migrate-iocs] rewrite %s: %v", fm.path, err)
			continue
		}
		total += n
		log.Printf("[migrate-iocs] rewrote %s (%d fix(es))", filepath.Base(fm.path), n)
	}
	log.Printf("[migrate-iocs] done — applied %d fix(es) across %d file(s)", total, len(affectedFiles))

	// Also fix feeds/unified.jsonl for each module.
	for _, mod := range modules {
		unified := filepath.Join(root, mod, "feeds", "unified.jsonl")
		if _, err := os.Stat(unified); err == nil {
			n, err := rewriteShardFixIOCs(unified, mod)
			if err != nil {
				log.Printf("[migrate-iocs] rewrite unified.jsonl [%s]: %v", mod, err)
			} else if n > 0 {
				log.Printf("[migrate-iocs] rewrote feeds/unified.jsonl [%s] (%d fix(es))", mod, n)
			}
		}
	}

	return nil
}

func scanShardForIOCIssues(path, mod string) ([]iocFix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	defAttack := defaultAttackType[mod]
	var out []iocFix
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4<<20), 4<<20)
	for sc.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
			continue
		}
		id, _ := raw["id"].(string)

		// Metadata: empty attack_type when we have a module default.
		if defAttack != "" {
			if at, _ := raw["attack_type"].(string); at == "" {
				out = append(out, iocFix{id, "empty-attack-type", defAttack})
			}
		}

		inds, _ := raw["indicators"].(map[string]any)
		if inds == nil {
			continue
		}

		for _, dom := range iocList(inds, "domains") {
			v := strings.TrimRight(dom, ".")
			if reIPv4.MatchString(v) {
				out = append(out, iocFix{id, "ip-as-domain", v})
			} else if strings.HasSuffix(dom, ".") {
				out = append(out, iocFix{id, "trailing-dot-domain", dom})
			}
		}

		for _, ip := range iocList(inds, "ips") {
			v := strings.TrimRight(ip, ".")
			if isPrivateIP(v) {
				out = append(out, iocFix{id, "private-ip", v})
			}
		}

		// URLs that lack a valid scheme should be removed.
		for _, u := range iocList(inds, "urls") {
			if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
				out = append(out, iocFix{id, "bad-url-scheme", u})
			}
		}
	}
	return out, sc.Err()
}

// iocList extracts the string values from an indicators sub-array.
func iocList(inds map[string]any, key string) []string {
	arr, _ := inds[key].([]any)
	var out []string
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		v, _ := m["value"].(string)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func rewriteShardFixIOCs(path, mod string) (int, error) {
	in, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	tmp := path + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}

	fixes := 0
	bw := bufio.NewWriterSize(out, 1<<20)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 4<<20), 4<<20)

	for sc.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
			fmt.Fprintln(bw, sc.Text())
			continue
		}

		changed := false

		// Metadata: backfill empty attack_type.
		if defAttack := defaultAttackType[mod]; defAttack != "" {
			if at, _ := raw["attack_type"].(string); at == "" {
				raw["attack_type"] = defAttack
				fixes++
				changed = true
			}
		}

		inds, _ := raw["indicators"].(map[string]any)
		if inds == nil {
			if changed {
				b, _ := json.Marshal(raw)
				bw.Write(b)
				bw.WriteByte('\n')
			} else {
				fmt.Fprintln(bw, sc.Text())
			}
			continue
		}

		// Collect existing IPs so we can dedup when moving domains→ips.
		existingIPs := map[string]bool{}
		for _, ip := range iocList(inds, "ips") {
			existingIPs[strings.TrimRight(ip, ".")] = true
		}

		// Process domains[]: reclassify IPs, strip trailing dots.
		doms, _ := inds["domains"].([]any)
		var cleanDoms []any
		var promotedIPs []any

		for _, item := range doms {
			m, ok := item.(map[string]any)
			if !ok {
				cleanDoms = append(cleanDoms, item)
				continue
			}
			v, _ := m["value"].(string)
			trimmed := strings.TrimRight(v, ".")

			if reIPv4.MatchString(trimmed) {
				// IP misclassified as domain.
				if !isPrivateIP(trimmed) && !existingIPs[trimmed] {
					newEntry := copyMap(m)
					newEntry["value"] = trimmed
					promotedIPs = append(promotedIPs, newEntry)
					existingIPs[trimmed] = true
				}
				fixes++
				changed = true
				continue
			}
			if trimmed != v {
				// Had trailing dot — strip it.
				newEntry := copyMap(m)
				newEntry["value"] = trimmed
				cleanDoms = append(cleanDoms, newEntry)
				fixes++
				changed = true
				continue
			}
			cleanDoms = append(cleanDoms, item)
		}
		if changed {
			inds["domains"] = cleanDoms
		}

		// Append promoted IPs to ips[].
		if len(promotedIPs) > 0 {
			existing, _ := inds["ips"].([]any)
			inds["ips"] = append(existing, promotedIPs...)
			changed = true
		}

		// Process ips[]: remove private/loopback addresses.
		ips, _ := inds["ips"].([]any)
		var cleanIPs []any
		for _, item := range ips {
			m, ok := item.(map[string]any)
			if !ok {
				cleanIPs = append(cleanIPs, item)
				continue
			}
			v, _ := m["value"].(string)
			trimmed := strings.TrimRight(v, ".")
			if isPrivateIP(trimmed) {
				fixes++
				changed = true
				continue
			}
			if trimmed != v {
				newEntry := copyMap(m)
				newEntry["value"] = trimmed
				cleanIPs = append(cleanIPs, newEntry)
				fixes++
				changed = true
				continue
			}
			cleanIPs = append(cleanIPs, item)
		}
		if changed {
			inds["ips"] = cleanIPs
		}

		// Process urls[]: remove entries without a valid http/https scheme.
		urls, _ := inds["urls"].([]any)
		var cleanURLs []any
		for _, item := range urls {
			m, ok := item.(map[string]any)
			if !ok {
				cleanURLs = append(cleanURLs, item)
				continue
			}
			v, _ := m["value"].(string)
			if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
				cleanURLs = append(cleanURLs, item)
			} else {
				fixes++
				changed = true
			}
		}
		if changed {
			inds["urls"] = cleanURLs
			raw["indicators"] = inds
		}

		if !changed {
			fmt.Fprintln(bw, sc.Text())
			continue
		}
		b, err := json.Marshal(raw)
		if err != nil {
			fmt.Fprintln(bw, sc.Text())
			continue
		}
		bw.Write(b)
		bw.WriteByte('\n')
	}

	if err := sc.Err(); err != nil {
		out.Close()
		os.Remove(tmp)
		return 0, err
	}
	if err := bw.Flush(); err != nil {
		out.Close()
		os.Remove(tmp)
		return 0, err
	}
	out.Close()
	return fixes, os.Rename(tmp, path)
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
