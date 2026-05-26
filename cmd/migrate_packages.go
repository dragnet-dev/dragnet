// Package cmd: `dragnet migrate-packages` strips false-positive package names
// from existing incident JSONL shards.
//
// The package parser in blogs/generic.go previously matched any word after
// "npm install" or "pip install" without validation, inserting common English
// words ("of", "that", "again"), punctuation-contaminated strings ("owners."),
// and single-letter tokens as package names. This command removes them.
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
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var migratePkgsCmd = &cobra.Command{
	Use:          "migrate-packages",
	Short:        "Strip false-positive package names from existing incident shards",
	SilenceUsage: true,
	RunE:         runMigratePackages,
}

var (
	migratePkgsApply bool
	migratePkgsRoot  string
	migratePkgsMods  string
)

func init() {
	migratePkgsCmd.Flags().BoolVar(&migratePkgsApply, "apply", false,
		"Write changes. Default is dry-run.")
	migratePkgsCmd.Flags().StringVar(&migratePkgsRoot, "root", "",
		"Root directory containing module subdirs (defaults to config file dir).")
	migratePkgsCmd.Flags().StringVar(&migratePkgsMods, "modules", "supply",
		"Comma-separated list of modules to migrate.")
	rootCmd.AddCommand(migratePkgsCmd)
}

// falsePositiveWords is a conservative denylist of strings that are definitely
// not package names — English prepositions, conjunctions, articles, pronouns,
// and a handful of HTML/prose tokens. It deliberately excludes short strings
// that ARE real packages (pg, ws, rc, got, tar, mem, uv, ai, etc.).
var falsePositiveWords = map[string]bool{
	// articles / prepositions / conjunctions
	"a": true, "an": true, "the": true, "of": true, "in": true, "on": true,
	"at": true, "by": true, "to": true, "or": true, "if": true, "as": true,
	"up": true, "no": true, "so": true, "and": true, "but": true, "nor": true,
	"for": true, "yet": true, "via": true, "per": true, "vs": true,
	// pronouns
	"i": true, "me": true, "my": true, "we": true, "us": true, "our": true,
	"he": true, "his": true, "him": true, "she": true, "her": true,
	"it": true, "its": true, "they": true, "them": true, "their": true,
	"you": true, "your": true, "who": true, "whom": true, "that": true,
	"this": true, "these": true, "those": true, "which": true,
	// common verbs / adverbs that appear in prose near install commands
	"is": true, "are": true, "was": true, "were": true, "be": true,
	"been": true, "being": true, "have": true, "has": true, "had": true,
	"do": true, "does": true, "did": true, "will": true, "would": true,
	"can": true, "could": true, "may": true, "might": true, "shall": true,
	"should": true, "must": true, "not": true, "now": true, "then": true,
	"also": true, "just": true, "only": true, "even": true, "both": true,
	"each": true, "more": true, "most": true, "than": true, "when": true,
	"with": true, "from": true, "into": true, "onto": true, "upon": true,
	"after": true, "again": true, "still": true, "about": true, "above": true,
	"below": true, "under": true, "over": true, "back": true, "such": true,
	"well": true, "very": true, "here": true, "there": true, "where": true,
	// misc prose / HTML tokens
	"null": true, "true": true, "false": true, "none": true,
	"div": true, "span": true, "href": true, "http": true, "https": true,
	"id": true, "class": true, "style": true, "type": true,
	"all": true, "any": true, "one": true, "two": true, "new": true,
	"old": true, "out": true, "off": true, "own": true, "how": true,
	"see": true, "try": true, "let": true, "run": true, "use": true,
	"set": true, "get": true, "put": true, "add": true,
}

// reTrailingPunct matches names that end with a punctuation character that
// no real package manager permits at the end of a name (. , ; ! ?).
// This catches "owners." where the parser consumed the trailing sentence dot.
// NB: hyphens, underscores, and brackets ARE used by real malicious packages
// (SEO-spam npm, Cyrillic typosquats) so we deliberately don't reject them.
var reTrailingPunct = regexp.MustCompile(`[.,;!?]$`)

// reSpaces matches names containing a whitespace character — prose fragments.
var reSpaces = regexp.MustCompile(`\s`)

// isFalsePkgName returns true when name is a parser false positive.
// Conservative by design: only removes names that CANNOT be a real package:
//   - empty strings
//   - names ending with sentence-terminating punctuation ("owners.")
//   - names containing whitespace (prose fragments)
//   - names matching the English word denylist ("of", "that", "again", "id")
//
// Deliberately preserved: Unicode/Cyrillic names (real typosquats),
// long hyphenated names (real SEO-spam packages), non-ASCII (real malicious).
func isFalsePkgName(name string) bool {
	if name == "" {
		return true
	}
	if reSpaces.MatchString(name) {
		return true
	}
	if reTrailingPunct.MatchString(name) {
		return true
	}
	if falsePositiveWords[strings.ToLower(name)] {
		return true
	}
	return false
}

func runMigratePackages(_ *cobra.Command, _ []string) error {
	root := migratePkgsRoot
	if root == "" {
		root = dataDir()
	}
	modules := strings.Split(migratePkgsMods, ",")

		var removals []pkgRemoval
	var affectedFiles []string

	for _, mod := range modules {
		allDir := filepath.Join(root, mod, "incidents", "all")
		entries, err := os.ReadDir(allDir)
		if err != nil {
			log.Printf("[migrate-packages][%s] read dir: %v (skipping)", mod, err)
			continue
		}

		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
				continue
			}
			path := filepath.Join(allDir, e.Name())
			fileRemovals, err := scanShardForFalsePkgs(path, mod)
			if err != nil {
				log.Printf("[migrate-packages][%s] scan %s: %v", mod, e.Name(), err)
				continue
			}
			if len(fileRemovals) > 0 {
				for _, r := range fileRemovals {
					removals = append(removals, r)
				}
				affectedFiles = append(affectedFiles, path)
			}
		}
	}

	if len(removals) == 0 {
		log.Printf("[migrate-packages] no false-positive package names found — already clean")
		return nil
	}

	log.Printf("[migrate-packages] found %d false-positive package name(s) across %d file(s):",
		len(removals), len(affectedFiles))
	for _, r := range removals {
		log.Printf("  [%s] %s — package %q (%s)", r.module, r.incidentID, r.pkgName, r.reason)
	}

	if !migratePkgsApply {
		log.Printf("[migrate-packages] DRY-RUN — re-run with --apply to remove them.")
		return nil
	}

	// Apply: rewrite each affected shard.
	total := 0
	for _, path := range affectedFiles {
		n, err := rewriteShardStripFalsePkgs(path)
		if err != nil {
			log.Printf("[migrate-packages] rewrite %s: %v", path, err)
			continue
		}
		total += n
		log.Printf("[migrate-packages] rewrote %s (%d removal(s))", filepath.Base(path), n)
	}
	log.Printf("[migrate-packages] done — removed %d false-positive package name(s) from %d file(s)",
		total, len(affectedFiles))

	// Also update feeds/unified.jsonl for each module.
	for _, mod := range modules {
		unified := filepath.Join(root, mod, "feeds", "unified.jsonl")
		if _, err := os.Stat(unified); err == nil {
			n, err := rewriteShardStripFalsePkgs(unified)
			if err != nil {
				log.Printf("[migrate-packages] rewrite unified.jsonl [%s]: %v", mod, err)
			} else if n > 0 {
				log.Printf("[migrate-packages] rewrote feeds/unified.jsonl [%s] (%d removal(s))", mod, n)
			}
		}
	}

	return nil
}

type pkgRemoval struct {
	incidentID string
	module     string
	pkgName    string
	ecosystem  string
	reason     string
}

func scanShardForFalsePkgs(path, mod string) ([]pkgRemoval, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []pkgRemoval
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4<<20), 4<<20)
	for sc.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
			continue
		}
		id, _ := raw["id"].(string)
		pkgs, _ := raw["packages"].([]any)
		for _, p := range pkgs {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			name, _ := pm["name"].(string)
			eco, _ := pm["ecosystem"].(string)
			if !isFalsePkgName(name) {
				continue
			}
			reason := "trailing punctuation"
			lower := strings.ToLower(name)
			switch {
			case name == "":
				reason = "empty"
			case reSpaces.MatchString(name):
				reason = "contains whitespace"
			case falsePositiveWords[lower]:
				reason = "common English word"
			}
			out = append(out, pkgRemoval{
				incidentID: id,
				module:     mod,
				pkgName:    name,
				ecosystem:  eco,
				reason:     reason,
			})
		}
	}
	return out, sc.Err()
}

func rewriteShardStripFalsePkgs(path string) (int, error) {
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

	removed := 0
	bw := bufio.NewWriterSize(out, 1<<20)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 4<<20), 4<<20)

	for sc.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
			fmt.Fprintln(bw, sc.Text())
			continue
		}

		pkgs, _ := raw["packages"].([]any)
		if len(pkgs) == 0 {
			fmt.Fprintln(bw, sc.Text())
			continue
		}

		filtered := make([]any, 0, len(pkgs))
		for _, p := range pkgs {
			pm, ok := p.(map[string]any)
			if !ok {
				filtered = append(filtered, p)
				continue
			}
			name, _ := pm["name"].(string)
			if isFalsePkgName(name) {
				removed++
				continue
			}
			filtered = append(filtered, pm)
		}

		if len(filtered) == 0 {
			raw["packages"] = nil
		} else {
			raw["packages"] = filtered
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
	return removed, os.Rename(tmp, path)
}
