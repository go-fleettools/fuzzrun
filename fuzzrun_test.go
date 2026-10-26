package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// execute runs the root command and returns stdout, stderr and the exit status
// main would have used.
func execute(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	cmd := RootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	err := cmd.Execute()
	code := 0
	if err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			code = ee.code
		} else {
			code = 2
		}
	}
	return out.String(), errb.String(), code
}

func write(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscover(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "go.mod"), "module m\n")
	write(t, filepath.Join(d, "a_test.go"), `package m
import "testing"
func FuzzA(f *testing.F) {}
func Fuzzy(f *testing.F) {}          // lower case after Fuzz: not a target
func FuzzTwo(f *testing.F, n int) {} // two parameters
func FuzzT(t *testing.T) {}          // wrong type
type X struct{}
func (X) FuzzM(f *testing.F) {}      // method
func FuzzB(f *testing.F) {}
`)
	write(t, filepath.Join(d, "sub", "deep", "b_test.go"), "package deep\nimport t \"testing\"\nfunc Fuzz(f *t.F) {}\n")
	write(t, filepath.Join(d, "sub", "c.go"), "package sub\nfunc FuzzNotATest(f *testing.F) {}\n")
	write(t, filepath.Join(d, "testdata", "x_test.go"), "package x\nimport \"testing\"\nfunc FuzzSkipped(f *testing.F) {}\n")
	write(t, filepath.Join(d, ".git", "x_test.go"), "package x\nimport \"testing\"\nfunc FuzzGit(f *testing.F) {}\n")

	got, err := discover(d, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []target{{"./.", "FuzzA"}, {"./.", "FuzzB"}, {"./sub/deep", "Fuzz"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	got, _ = discover(d, []string{"sub/..."})
	if want := []target{{"./sub/deep", "Fuzz"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered: got %v, want %v", got, want)
	}
	if got, _ = discover(d, []string{"./."}); len(got) != 2 {
		t.Fatalf("root pattern: %v", got)
	}
}

func TestDiscoverSyntaxError(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "a_test.go"), "package m\nfunc (")
	if _, err := discover(d, nil); err == nil {
		t.Fatal("a file that does not parse must be an error, not zero targets")
	}
}

func TestParseCrasher(t *testing.T) {
	out := "fuzz: elapsed: 0s\n--- FAIL: FuzzBad (0.01s)\n    --- FAIL: FuzzBad (0.00s)\n    Failing input written to testdata/fuzz/FuzzBad/abc123\n    To re-run:\n"
	for pkg, want := range map[string]string{
		"./.":       "testdata/fuzz/FuzzBad/abc123",
		"./sub/pkg": "sub/pkg/testdata/fuzz/FuzzBad/abc123",
	} {
		if got, ok := parseCrasher(out, pkg); !ok || got != want {
			t.Errorf("%s: got %q %v, want %q", pkg, got, ok, want)
		}
	}
	if p, ok := parseCrasher("FAIL\texample.com/x\t0.1s\n", "./."); ok {
		t.Fatalf("no crasher line, got %q", p)
	}
}

func TestParseLoadavg(t *testing.T) {
	if v, err := parseProcLoadavg([]byte("1.25 0.5 0.1 1/200 999\n")); err != nil || v != 1.25 {
		t.Fatalf("proc: %v %v", v, err)
	}
	if _, err := parseProcLoadavg([]byte("")); err == nil {
		t.Fatal("empty proc must fail")
	}
	b := make([]byte, 24)
	binary.NativeEndian.PutUint32(b[0:], 2048*3) // 3.0 with scale 2048
	binary.NativeEndian.PutUint64(b[16:], 2048)
	if v, err := parseSysctlLoadavg(b); err != nil || v != 3 {
		t.Fatalf("sysctl: %v %v", v, err)
	}
	if _, err := parseSysctlLoadavg(b[:8]); err == nil {
		t.Fatal("short sysctl value must fail")
	}
}

// TestReadLoadAvgLive reads the real load average where the platform has one.
func TestReadLoadAvgLive(t *testing.T) {
	v, err := readLoadAvg()
	if err != nil {
		t.Skipf("not readable here: %v", err)
	}
	if v < 0 || v > 100000 {
		t.Fatalf("implausible load %v", v)
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestRunPlanted fuzzes a module holding one passing and one planted failing
// target. The module is copied first: the failing run writes its corpus entry
// under testdata/fuzz, and that must never land in the repository.
func TestRunPlanted(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the go tool for several seconds")
	}
	mod := filepath.Join(t.TempDir(), "planted")
	copyTree(t, filepath.Join("testdata", "planted"), mod)

	var code int
	oldExit := osExit
	osExit = func(c int) { code = c }
	defer func() { osExit = oldExit }()

	out, errb, c := execute(t, "run", "--dir", mod, "--time", "5s", "--jobs", "2", "--logs", filepath.Join(t.TempDir(), "logs"))
	osExit(c) // what main does with the status
	if code != 1 {
		t.Fatalf("exit status %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, errb)
	}
	summary := out[strings.Index(out, "== summary =="):]
	if !strings.Contains(summary, "PASS ./. FuzzGood") {
		t.Errorf("FuzzGood not PASS:\n%s", summary)
	}
	if !strings.Contains(summary, "CRASH ./. FuzzBad") {
		t.Fatalf("FuzzBad not CRASH:\n%s", summary)
	}
	if !strings.Contains(summary, "testdata/fuzz/FuzzBad/") {
		t.Errorf("no corpus path for FuzzBad:\n%s", summary)
	}
	entries, err := os.ReadDir(filepath.Join(mod, "testdata", "fuzz", "FuzzBad"))
	if err != nil || len(entries) == 0 {
		t.Errorf("the corpus entry the summary names does not exist: %v", err)
	}
	if !strings.Contains(summary, "2 targets: 1 PASS, 0 FAIL, 1 CRASH") {
		t.Errorf("totals:\n%s", summary)
	}
	// The repository copy must be untouched.
	if _, err := os.Stat(filepath.Join("testdata", "planted", "testdata")); err == nil {
		t.Error("a corpus was written into the repository")
	}
}

func TestRunCouldNotRun(t *testing.T) {
	d := t.TempDir()
	if _, _, c := execute(t, "run", "--dir", d); c != 2 {
		t.Errorf("no module: status %d, want 2", c)
	}
	write(t, filepath.Join(d, "go.mod"), "module m\n")
	if _, _, c := execute(t, "run", "--dir", d); c != 2 {
		t.Errorf("no targets: status %d, want 2", c)
	}
	if _, _, c := execute(t, "run", "--dir", d, "--jobs", "0"); c != 2 {
		t.Errorf("jobs 0: status %d, want 2", c)
	}
	if _, _, c := execute(t, "run", "--dir", d, "--time", "soon"); c != 2 {
		t.Errorf("bad time: status %d, want 2", c)
	}
}

func TestMaxLoadUnreadable(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "go.mod"), "module m\n")
	old := loadAvg
	loadAvg = func() (float64, error) { return 0, errors.New("no sysctl") }
	defer func() { loadAvg = old }()
	_, errb, c := execute(t, "run", "--dir", d, "--max-load", "4")
	if c != 2 {
		t.Fatalf("status %d, want 2 (%s)", c, errb)
	}
}

func TestWaitForLoad(t *testing.T) {
	old, oldPoll := loadAvg, loadPoll
	defer func() { loadAvg, loadPoll = old, oldPoll }()
	loadPoll = time.Millisecond
	calls := 0
	loadAvg = func() (float64, error) {
		calls++
		if calls < 4 {
			return 9, nil
		}
		return 1, nil
	}
	var errb bytes.Buffer
	var mu sync.Mutex
	waitForLoad(&errb, &mu, target{"./.", "FuzzA"}, 2)
	if calls != 4 || !strings.Contains(errb.String(), "waits") {
		t.Fatalf("calls %d, stderr %q", calls, errb.String())
	}
}

func TestWait(t *testing.T) {
	f := filepath.Join(t.TempDir(), "log")
	// timeout: the file does not exist, then lacks the substring
	if out, _, c := execute(t, "wait", f, "done", "--timeout", "100ms", "--interval", "10ms"); c != 1 || !strings.Contains(out, "timeout") {
		t.Fatalf("missing file: status %d out %q", c, out)
	}
	write(t, f, "starting\n")
	if _, _, c := execute(t, "wait", f, "done", "--timeout", "100ms", "--interval", "10ms"); c != 1 {
		t.Fatalf("absent substring: status %d, want 1", c)
	}
	// found immediately
	write(t, f, "starting\nall done\n")
	if out, _, c := execute(t, "wait", f, "done", "--timeout", "1s"); c != 0 || !strings.Contains(out, "found") {
		t.Fatalf("present: status %d out %q", c, out)
	}
	// found after the file is written later
	g := filepath.Join(t.TempDir(), "later")
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = os.WriteFile(g, []byte("ready"), 0o644)
	}()
	if _, _, c := execute(t, "wait", g, "ready", "--timeout", "5s", "--interval", "20ms"); c != 0 {
		t.Fatalf("late write: status %d", c)
	}
	// errors
	if _, _, c := execute(t, "wait", t.TempDir(), "x", "--timeout", "1s"); c != 2 {
		t.Fatalf("directory: status %d, want 2", c)
	}
	if _, _, c := execute(t, "wait", f, "x", "--interval", "0s"); c != 2 {
		t.Fatalf("interval 0: status %d, want 2", c)
	}
}
