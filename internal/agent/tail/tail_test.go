package tail

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFollowAndRotate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "access.log")
	os.WriteFile(p, []byte("old line\n"), 0o644)
	out := make(chan Line, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go (&Tailer{Patterns: []string{filepath.Join(dir, "*.log")}, Out: out}).Run(ctx)
	time.Sleep(300 * time.Millisecond)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("new 1\nnew")
	f.Close()
	expect(t, out, "new 1\n")
	f, _ = os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(" 2\n")
	f.Close()
	expect(t, out, "new 2\n")
	os.Rename(p, p+".1") // rotate
	os.WriteFile(p, []byte("after rotate\n"), 0o644)
	expect(t, out, "after rotate\n")
}

func expect(t *testing.T, out chan Line, want string) {
	t.Helper()
	select {
	case l := <-out:
		if l.Text != want {
			t.Fatalf("got %q want %q", l.Text, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for %q", want)
	}
}

func TestSkipRotated(t *testing.T) {
	for _, n := range []string{"access.log.1", "access.log.2.gz", "access.log-20261116"} {
		if !skipName(n) {
			t.Errorf("%s not skipped", n)
		}
	}
	if skipName("access.log") || skipName("u_ex261116.log") {
		t.Error("live log skipped")
	}
}

func TestStateFileNullAndEarlySave(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "offsets.json")
	tl := &Tailer{StatePath: state}
	tl.Save() // before Run: must not write "null"
	if _, err := os.Stat(state); err == nil {
		t.Fatal("Save before Run wrote a state file")
	}
	os.WriteFile(state, []byte("null"), 0o600)
	if m := tl.load(); m == nil {
		t.Fatal("null state file gave a nil map")
	}
}
