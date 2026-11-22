package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func putFile(t *testing.T, p string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Repeat("x", n)), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSeedCorpusKeepsSmallestAndSkipsBig(t *testing.T) {
	cache, dir := t.TempDir(), t.TempDir()
	for i, n := range []int{5, 1, 3, 9, 70000} {
		putFile(t, filepath.Join(cache, "FuzzA", string(rune('a'+i))), n)
	}
	putFile(t, filepath.Join(cache, "FuzzB", "z"), 2)
	out, _, code := execute(t, "seedcorpus", "--cache", cache, "--dir", dir, "--max", "3")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "FuzzA: 3 files") || !strings.Contains(out, "FuzzB: 1 files") || !strings.Contains(out, "total 4") {
		t.Errorf("output:\n%s", out)
	}
	got, _ := os.ReadDir(filepath.Join(dir, "testdata", "fuzz", "FuzzA"))
	names := ""
	for _, e := range got {
		names += e.Name()
	}
	if names != "abc" { // files a=5 b=1 c=3 kept; d=9 cut by --max, e=70000 over --max-bytes
		t.Errorf("kept %q, want abc", names)
	}
}

func TestSeedCorpusDefaultCacheNeedsModule(t *testing.T) {
	_, _, code := execute(t, "seedcorpus", "--dir", t.TempDir())
	if code != 2 {
		t.Errorf("exit %d, want 2 (no go.mod)", code)
	}
}

func TestSeedCorpusMissingCache(t *testing.T) {
	_, _, code := execute(t, "seedcorpus", "--cache", filepath.Join(t.TempDir(), "none"), "--dir", t.TempDir())
	if code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
}

func TestDefaultCacheNamesTheModule(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/m\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := defaultCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(filepath.ToSlash(c), "/fuzz/example.com/m") {
		t.Errorf("cache %q", c)
	}
}

func TestScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/old/"):
			w.Write([]byte("go run fuzzrun@v0.5.0\nif [ \"$status\" -ge 2 ]; then"))
		case strings.Contains(r.URL.Path, "/new/"):
			w.Write([]byte("go run fuzzrun@v0.8.0"))
		case strings.Contains(r.URL.Path, "/boom/"):
			http.Error(w, "x", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	out, _, code := execute(t, "scan", "--org", "o", "--base", srv.URL, "new", "none")
	if code != 0 || !strings.Contains(out, "o/new fuzzrun=true tolerant=false") || !strings.Contains(out, "o/none no fuzz.yml") {
		t.Errorf("exit %d\n%s", code, out)
	}
	out, _, code = execute(t, "scan", "--org", "o", "--base", srv.URL, "old")
	if code != 1 || !strings.Contains(out, "tolerant=true") {
		t.Errorf("exit %d\n%s", code, out)
	}
	out, _, code = execute(t, "scan", "--org", "o", "--base", srv.URL, "boom")
	if code != 1 || !strings.Contains(out, "NOT READ HTTP 500") {
		t.Errorf("exit %d\n%s", code, out)
	}
	_, _, code = execute(t, "scan", "--base", srv.URL, "x")
	if code != 2 {
		t.Errorf("no --org: exit %d, want 2", code)
	}
	out, _, code = execute(t, "scan", "--org", "o", "--base", "http://127.0.0.1:1", "x")
	if code != 1 || !strings.Contains(out, "NOT READ") {
		t.Errorf("unreachable: exit %d\n%s", code, out)
	}
}
