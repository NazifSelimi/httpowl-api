// Package tail follows log files (by glob), surviving rotation and truncation,
// and remembers offsets so restarts don't lose or repeat lines.
package tail

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Line struct {
	File string
	Text string
}

type fileState struct {
	Offset int64  `json:"offset"`
	ID     string `json:"id"` // inode/size fingerprint
}

// Tailer follows every file matching Patterns.
type Tailer struct {
	Patterns  []string
	StatePath string // optional JSON file for offsets
	Out       chan<- Line

	mu    sync.Mutex
	state map[string]fileState
}

// Files returns the current matches (no rotated/compressed files).
func Files(patterns []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range patterns {
		ms, _ := filepath.Glob(p)
		for _, m := range ms {
			if seen[m] || skipName(m) {
				continue
			}
			if fi, err := os.Stat(m); err != nil || !fi.Mode().IsRegular() {
				continue
			}
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

func skipName(n string) bool {
	b := strings.ToLower(filepath.Base(n))
	for _, s := range []string{".gz", ".zip", ".bz2", ".xz", ".old", ".bak"} {
		if strings.HasSuffix(b, s) {
			return true
		}
	}
	// access.log.1, access.log-20261116
	ext := filepath.Ext(b)
	if len(ext) > 1 && strings.Trim(ext[1:], "0123456789") == "" {
		return true
	}
	return strings.Contains(b, ".log-")
}

// Run polls files every second until ctx ends.
func (t *Tailer) Run(ctx context.Context) {
	loaded := t.load()
	t.mu.Lock()
	t.state = loaded
	t.mu.Unlock()
	first := true
	readers := map[string]*follower{}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	lastGlob := time.Time{}
	for {
		if time.Since(lastGlob) > 15*time.Second {
			lastGlob = time.Now()
			for _, f := range Files(t.Patterns) {
				if readers[f] == nil {
					fl := &follower{path: f}
					st, known := t.state[f]
					switch {
					case known:
						fl.offset, fl.id = st.Offset, st.ID
					case first:
						fl.fromEnd = true // existing file at startup: only new lines
					}
					readers[f] = fl
					slog.Info("following log", "file", f)
				}
			}
			first = false
		}
		for f, fl := range readers {
			if err := fl.poll(ctx, t.Out); err != nil {
				if os.IsNotExist(err) {
					delete(readers, f)
					t.mu.Lock()
					delete(t.state, f)
					t.mu.Unlock()
					continue
				}
				slog.Warn("read log", "file", f, "err", err)
			}
			t.mu.Lock()
			t.state[f] = fileState{Offset: fl.offset, ID: fl.id}
			t.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			t.Save()
			return
		case <-tick.C:
		}
	}
}

// Save writes offsets to StatePath.
func (t *Tailer) Save() {
	if t.StatePath == "" {
		return
	}
	t.mu.Lock()
	if t.state == nil { // Run has not started yet: nothing to save
		t.mu.Unlock()
		return
	}
	b, _ := json.Marshal(t.state)
	t.mu.Unlock()
	tmp := t.StatePath + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, t.StatePath)
	}
}

func (t *Tailer) load() map[string]fileState {
	m := map[string]fileState{}
	if t.StatePath != "" {
		if b, err := os.ReadFile(t.StatePath); err == nil {
			_ = json.Unmarshal(b, &m)
		}
	}
	if m == nil { // a file containing "null"
		m = map[string]fileState{}
	}
	return m
}

type follower struct {
	path    string
	offset  int64
	id      string
	fromEnd bool
	partial string
}

func (f *follower) poll(ctx context.Context, out chan<- Line) error {
	fh, err := os.Open(f.path)
	if err != nil {
		return err
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return err
	}
	id := fileID(fi)
	if f.fromEnd {
		f.offset, f.id, f.fromEnd = fi.Size(), id, false
		return nil
	}
	if (f.id != "" && id != f.id) || fi.Size() < f.offset { // rotated or truncated
		f.offset, f.partial = 0, ""
	}
	f.id = id
	if fi.Size() == f.offset {
		return nil
	}
	if _, err := fh.Seek(f.offset, io.SeekStart); err != nil {
		return err
	}
	br := bufio.NewReaderSize(fh, 64*1024)
	for n := 0; n < 20000; n++ { // cap per poll so one huge file can't starve the rest
		s, err := br.ReadString('\n')
		f.offset += int64(len(s))
		if err != nil { // incomplete last line: keep for next poll
			f.partial += s
			break
		}
		s = f.partial + s
		f.partial = ""
		if len(s) > 16*1024 {
			continue
		}
		select {
		case out <- Line{File: f.path, Text: s}:
		case <-ctx.Done():
			return nil
		}
	}
	return nil
}
