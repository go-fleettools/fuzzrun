package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// runErr runs the command tree and returns the error text main would print.
func runErr(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	cmd := RootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("no error for %v\n%s", args, out.String())
	}
	return err.Error()
}

func skipIfRoot(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits are not enforced here")
	}
}

func TestSeedCorpusErrorsNameTheirCause(t *testing.T) {
	if msg := runErr(t, "seedcorpus", "--dir", t.TempDir()); !strings.Contains(msg, "go.mod") || strings.Contains(msg, "no module line") {
		t.Errorf("no go.mod must be the open error, not a missing module line: %q", msg)
	}

	empty := t.TempDir()
	if err := os.WriteFile(filepath.Join(empty, "go.mod"), []byte("// nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if msg := runErr(t, "seedcorpus", "--dir", empty); !strings.Contains(msg, "no module line") {
		t.Errorf("no module line: %q", msg)
	}

	withMod := t.TempDir()
	if err := os.WriteFile(filepath.Join(withMod, "go.mod"), []byte("module example.com/m\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	if msg := runErr(t, "seedcorpus", "--dir", withMod); !strings.Contains(msg, "go env GOCACHE") {
		t.Errorf("no go tool: %q", msg)
	}

	none := filepath.Join(t.TempDir(), "none")
	if msg := runErr(t, "seedcorpus", "--cache", none, "--dir", t.TempDir()); !strings.Contains(msg, none) {
		t.Errorf("missing cache: %q", msg)
	}
}

func TestSeedCorpusTiesBreakByPath(t *testing.T) {
	cache, dir := t.TempDir(), t.TempDir()
	putFile(t, filepath.Join(cache, "FuzzA", "b"), 4)
	putFile(t, filepath.Join(cache, "FuzzA", "a"), 4)
	putFile(t, filepath.Join(cache, "FuzzA", "c"), 2)
	if _, _, code := execute(t, "seedcorpus", "--cache", cache, "--dir", dir, "--max", "2"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	got, _ := os.ReadDir(filepath.Join(dir, "testdata", "fuzz", "FuzzA"))
	names := ""
	for _, e := range got {
		names += e.Name()
	}
	if names != "ac" { // smallest first (c), then the equal-size pair by path (a before b)
		t.Errorf("kept %q, want ac", names)
	}
}

func TestSeedCorpusFileSystemFailures(t *testing.T) {
	skipIfRoot(t)

	// An unreadable target directory.
	cache := t.TempDir()
	putFile(t, filepath.Join(cache, "FuzzA", "a"), 1)
	if err := os.Chmod(filepath.Join(cache, "FuzzA"), 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Join(cache, "FuzzA"), 0o755)
	if msg := runErr(t, "seedcorpus", "--cache", cache, "--dir", t.TempDir()); !strings.Contains(msg, "FuzzA") {
		t.Errorf("unreadable target: %q", msg)
	}

	// testdata is a regular file: the corpus directory cannot be made.
	cache = t.TempDir()
	putFile(t, filepath.Join(cache, "FuzzA", "a"), 1)
	dir := t.TempDir()
	putFile(t, filepath.Join(dir, "testdata"), 1)
	if msg := runErr(t, "seedcorpus", "--cache", cache, "--dir", dir); !strings.Contains(msg, "testdata") {
		t.Errorf("mkdir: %q", msg)
	}

	// Nothing to copy, yet the corpus directory still cannot be made.
	cache = t.TempDir()
	if err := os.MkdirAll(filepath.Join(cache, "FuzzA"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	putFile(t, filepath.Join(dir, "testdata"), 1)
	if msg := runErr(t, "seedcorpus", "--cache", cache, "--dir", dir); !strings.Contains(msg, "testdata") {
		t.Errorf("mkdir with no files: %q", msg)
	}

	// A cached file that cannot be read.
	cache = t.TempDir()
	f := filepath.Join(cache, "FuzzA", "a")
	putFile(t, f, 1)
	if err := os.Chmod(f, 0); err != nil {
		t.Fatal(err)
	}
	if msg := runErr(t, "seedcorpus", "--cache", cache, "--dir", t.TempDir()); !strings.Contains(msg, "FuzzA") {
		t.Errorf("unreadable file: %q", msg)
	}

	// A corpus directory that cannot be written.
	cache = t.TempDir()
	putFile(t, filepath.Join(cache, "FuzzA", "a"), 1)
	dir = t.TempDir()
	out := filepath.Join(dir, "testdata", "fuzz", "FuzzA")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(out, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(out, 0o755)
	if msg := runErr(t, "seedcorpus", "--cache", cache, "--dir", dir); !strings.Contains(msg, "FuzzA") {
		t.Errorf("write: %q", msg)
	}
}

func TestScanBodyReadFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Write([]byte("short"))
		if h, ok := w.(http.Hijacker); ok {
			c, _, _ := h.Hijack()
			c.Close()
		}
	}))
	defer srv.Close()
	out, _, code := execute(t, "scan", "--org", "o", "--base", srv.URL, "r")
	if code != 1 || !strings.Contains(out, "o/r NOT READ") {
		t.Errorf("exit %d\n%s", code, out)
	}
}
