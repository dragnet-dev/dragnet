package stix

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// MaxBundleShardBytes caps each STIX bundle file at 40 MB so we stay
// comfortably under GitHub's 100 MB single-file hard reject. The actual
// shard size is approximate — we cut after the object that pushes us
// over, so a single very large object can land slightly above the cap.
const MaxBundleShardBytes = 40 * 1024 * 1024

// BuildCombinedBundle merges all per-incident bundles into a single bundle.
// Objects are deduplicated by STIX ID so shared objects (same threat actor
// across multiple incidents) appear only once.
//
// Prefer WriteCombinedBundleShards for the bulk path — this materialises
// the full object slice in memory, which crosses 100 MB on the 300k+
// combined bundles dragnet generates today. Kept for test fixtures and
// any out-of-band caller that genuinely needs a `Bundle` value.
func BuildCombinedBundle(bundles []Bundle) Bundle {
	seen := map[string]bool{}
	objects := []any{}

	for _, b := range bundles {
		for _, obj := range b.Objects {
			id := objectID(obj)
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			objects = append(objects, obj)
		}
	}

	return Bundle{
		Type:    "bundle",
		ID:      StixID("bundle", "dragnet:all"),
		Objects: objects,
	}
}

// WriteCombinedBundleShards writes a deduped combined bundle to one or more
// shard files under dir. The first file is named "{base}.json" if it fits
// in a single shard, otherwise "{base}-0.json", "{base}-1.json", etc. Each
// shard is a self-contained valid STIX 2.1 bundle (own `id`, own `objects`
// array) so SIEM/TIP consumers can ingest them in any order.
//
// Compact JSON (no indentation) is used because bundle.json is consumed by
// software, not humans, and pretty-printing adds ~30% to encode time +
// ~3× to file size. Validation is intentionally skipped here: per-incident
// bundles weren't validated either (validation cost dominated the v0.1.7
// hang), and the combined doc is purely a flatten + dedupe of sub-bundles,
// so no new schema-level invariants need checking.
//
// Memory: peak stays O(one object + the running dedupe-id set) instead of
// O(all objects). Even after the v0.1.8 curated cap, the unsharded write
// would land ~125-250 MB compact JSON across 5 modules' worth of bundles.
//
// Returns the list of relative shard filenames written, in order.
func WriteCombinedBundleShards(dir, base string, bundles []Bundle) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	// Wipe stale shards from prior runs (different shard count, different
	// dedupe outcome) so leftovers don't masquerade as fresh output.
	if entries, _ := os.ReadDir(dir); len(entries) > 0 {
		for _, e := range entries {
			name := e.Name()
			if name == base+".json" {
				_ = os.Remove(filepath.Join(dir, name))
				continue
			}
			// Match base-<N>.json
			if len(name) > len(base)+6 && name[:len(base)+1] == base+"-" && name[len(name)-5:] == ".json" {
				_ = os.Remove(filepath.Join(dir, name))
			}
		}
	}

	seen := map[string]bool{}

	// Flatten + dedupe in a single pass without materialising the full slice.
	// We need to know up-front whether the final result fits in one shard so
	// we can pick the no-suffix filename, but the only way to know that is
	// to encode everything. Approach: encode into a sharded writer that
	// names files as bundle-0.json / bundle-1.json from the start, then
	// rename bundle-0.json → bundle.json at the end iff only one shard was
	// produced.
	w := newShardWriter(dir, base)

	for _, b := range bundles {
		for _, obj := range b.Objects {
			id := objectID(obj)
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			if err := w.write(obj); err != nil {
				return nil, err
			}
		}
	}
	return w.close()
}

// shardWriter encodes STIX objects into one or more bundle shard files,
// rolling to a new file when the current one would exceed MaxBundleShardBytes.
type shardWriter struct {
	dir      string
	base     string
	idx      int
	written  []string
	cur      *os.File
	buf      *bufio.Writer
	enc      *json.Encoder
	bytes    int
	wroteAny bool
}

func newShardWriter(dir, base string) *shardWriter {
	return &shardWriter{dir: dir, base: base}
}

func (s *shardWriter) openNext() error {
	if err := s.closeCurrent(true); err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%d.json", s.base, s.idx)
	s.idx++
	path := filepath.Join(s.dir, name)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	s.cur = f
	s.buf = bufio.NewWriterSize(f, 1<<16)
	s.enc = json.NewEncoder(s.buf)
	s.enc.SetEscapeHTML(false)
	s.written = append(s.written, name)
	s.bytes = 0
	s.wroteAny = false

	bundleID := StixID("bundle", fmt.Sprintf("dragnet:all:%d", s.idx-1))
	header := fmt.Sprintf(`{"type":"bundle","id":%q,"objects":[`, bundleID)
	if _, err := s.buf.WriteString(header); err != nil {
		return err
	}
	s.bytes += len(header)
	return nil
}

func (s *shardWriter) closeCurrent(suppressErr bool) error {
	if s.cur == nil {
		return nil
	}
	if _, err := s.buf.WriteString("]}"); err != nil && !suppressErr {
		return err
	}
	if err := s.buf.Flush(); err != nil && !suppressErr {
		return err
	}
	if err := s.cur.Close(); err != nil && !suppressErr {
		return err
	}
	s.cur = nil
	s.buf = nil
	s.enc = nil
	return nil
}

func (s *shardWriter) write(obj any) error {
	if s.cur == nil {
		if err := s.openNext(); err != nil {
			return err
		}
	}

	// Pre-encode to know the byte cost without committing it yet — Encoder
	// would otherwise write straight to the underlying buf and we'd have
	// to live with a slightly-over-cap shard whenever the last object is
	// large.
	tmp, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	// +1 for the comma separator between objects (if any), +1 for the
	// trailing newline json.Encoder always emits.
	needed := len(tmp) + 2

	if s.wroteAny && s.bytes+needed > MaxBundleShardBytes {
		if err := s.closeCurrent(false); err != nil {
			return err
		}
		if err := s.openNext(); err != nil {
			return err
		}
	}

	if s.wroteAny {
		if _, err := s.buf.WriteString(","); err != nil {
			return err
		}
		s.bytes++
	}
	if _, err := s.buf.Write(tmp); err != nil {
		return err
	}
	if _, err := s.buf.WriteString("\n"); err != nil {
		return err
	}
	s.bytes += len(tmp) + 1
	s.wroteAny = true
	return nil
}

func (s *shardWriter) close() ([]string, error) {
	if err := s.closeCurrent(false); err != nil {
		return nil, err
	}
	// If only one shard was written, rename to {base}.json (no suffix) so
	// consumers without sharding logic can fetch a stable single path.
	if len(s.written) == 1 {
		oldPath := filepath.Join(s.dir, s.written[0])
		newName := s.base + ".json"
		newPath := filepath.Join(s.dir, newName)
		if err := os.Rename(oldPath, newPath); err != nil {
			return nil, err
		}
		s.written = []string{newName}
	}
	return s.written, nil
}

// objectID extracts the STIX ID from any STIX object using a type switch.
func objectID(obj any) string {
	switch v := obj.(type) {
	case Identity:
		return v.ID
	case Indicator:
		return v.ID
	case Malware:
		return v.ID
	case ThreatActor:
		return v.ID
	case Campaign:
		return v.ID
	case AttackPattern:
		return v.ID
	case Vulnerability:
		return v.ID
	case Relationship:
		return v.ID
	}
	return ""
}
