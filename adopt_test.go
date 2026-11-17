package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner answers git, gitpush and gh from a handler and records the calls.
type fakeRunner struct {
	calls   []string
	handler func(tool string, args []string) (string, error)
}

func (f *fakeRunner) Run(dir, tool string, args ...string) (string, error) {
	f.calls = append(f.calls, tool+" "+strings.Join(args, " "))
	return f.handler(tool, args)
}

func (f *fakeRunner) called(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func withRunner(t *testing.T, f *fakeRunner) {
	t.Helper()
	old := newRunner
	newRunner = func() runner { return f }
	t.Cleanup(func() { newRunner = old })
}

func adoptRepo(t *testing.T) string {
	d := t.TempDir()
	write(t, filepath.Join(d, "go.mod"), "module m\n")
	write(t, filepath.Join(d, "a_test.go"), "package m\nimport \"testing\"\nfunc FuzzA(f *testing.F) {}\n")
	if err := os.MkdirAll(filepath.Join(d, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

const testSHA = "0123456789abcdef0123456789abcdef01234567"

func TestAdoptOpen(t *testing.T) {
	d := adoptRepo(t)
	f := &fakeRunner{handler: func(tool string, a []string) (string, error) {
		switch {
		case tool == "git" && a[0] == "remote":
			return "https://github.com/o/r.git\n", nil
		case tool == "gh":
			return "https://github.com/o/r/pull/7\n", nil
		}
		return "", nil
	}}
	withRunner(t, f)
	out, _, code := execute(t, "adopt", "open", "--dir", d)
	if code != 0 || !strings.Contains(out, "https://github.com/o/r/pull/7") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	b := readFile(t, filepath.Join(d, ".github/workflows/fuzz.yml"))
	if !strings.Contains(b, triggerText) || !strings.Contains(b, "fuzzrun@"+fuzzrunVersion) {
		t.Fatalf("workflow:\n%s", b)
	}
	// order: branch from origin/HEAD, two commits, push, then the PR.
	want := []string{"git status", "git remote", "git fetch origin", "git checkout -b fuzzrun-workflow origin/HEAD",
		"git add", "git commit -m fuzz: a nightly", "git commit -a -m fuzz: temporary", "gitpush -u origin fuzzrun-workflow", "gh pr create --repo o/r"}
	i := 0
	for _, c := range f.calls {
		if i < len(want) && strings.HasPrefix(c, want[i]) {
			i++
		}
	}
	if i != len(want) {
		t.Fatalf("calls out of order, matched %d of %d:\n%s", i, len(want), strings.Join(f.calls, "\n"))
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "git commit") && !strings.Contains(c, attribution) {
			t.Errorf("no attribution: %s", c)
		}
	}
	if !strings.Contains(readFile(t, filepath.Join(d, ".git/fuzzrun-pr-body.md")), "Generated with [Claude Code]") {
		t.Error("PR body lacks the attribution")
	}
}

func TestAdoptOpenRefusals(t *testing.T) {
	d := adoptRepo(t)
	dirty := &fakeRunner{handler: func(tool string, a []string) (string, error) {
		if a[0] == "status" {
			return " M x.go\n", nil
		}
		return "", nil
	}}
	withRunner(t, dirty)
	if _, _, code := execute(t, "adopt", "open", "--dir", d); code != 2 || dirty.called("git checkout") {
		t.Fatalf("dirty tree: exit %d, calls %v", code, dirty.calls)
	}
	// a repository that already runs fuzzrun: nothing to change, exit 2, nothing pushed.
	write(t, filepath.Join(d, ".github/workflows/fuzz.yml"), freshWorkflow)
	ok := &fakeRunner{handler: func(tool string, a []string) (string, error) {
		if a[0] == "remote" {
			return "git@github.com:o/r.git\n", nil
		}
		return "", nil
	}}
	withRunner(t, ok)
	if _, _, code := execute(t, "adopt", "open", "--dir", d); code != 2 || ok.called("gitpush") {
		t.Fatalf("already adopted: exit %d, calls %v", code, ok.calls)
	}
	if _, _, code := execute(t, "adopt", "open", "--dir", t.TempDir()); code != 2 {
		t.Fatalf("no go.mod: exit %d", code)
	}
}

type finishCase struct {
	runSHA     string
	status     string
	jobs       string
	log        string
	wantCode   int
	wantPushed bool
	wantInOut  string
}

func finishRepo(t *testing.T) string {
	d := adoptRepo(t)
	w, err := addTrigger(freshWorkflow)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(d, ".github/workflows/fuzz.yml"), w)
	return d
}

func runFinish(t *testing.T, c finishCase) (*fakeRunner, string) {
	d := finishRepo(t)
	f := &fakeRunner{handler: func(tool string, a []string) (string, error) {
		switch {
		case tool == "git" && a[0] == "remote":
			return "https://github.com/o/r\n", nil
		case tool == "git" && a[0] == "rev-parse" && a[1] == "--abbrev-ref":
			return "fuzzrun-workflow\n", nil
		case tool == "git" && a[0] == "rev-parse":
			return testSHA + "\n", nil
		case tool == "gh" && a[1] == "list":
			return `[{"databaseId":99,"headSha":"` + c.runSHA + `","status":"` + c.status + `","conclusion":"success"}]`, nil
		case tool == "gh" && a[1] == "view" && strings.Contains(strings.Join(a, " "), "--log"):
			return c.log, nil
		case tool == "gh" && a[1] == "view":
			return c.jobs, nil
		}
		return "", nil
	}}
	withRunner(t, f)
	out, _, code := execute(t, "adopt", "finish", "--dir", d)
	if code != c.wantCode {
		t.Fatalf("exit %d, want %d\n%s\ncalls:\n%s", code, c.wantCode, out, strings.Join(f.calls, "\n"))
	}
	if pushed := f.called("gitpush"); pushed != c.wantPushed {
		t.Fatalf("pushed=%v, want %v", pushed, c.wantPushed)
	}
	if c.wantInOut != "" && !strings.Contains(out, c.wantInOut) {
		t.Fatalf("output lacks %q:\n%s", c.wantInOut, out)
	}
	b := readFile(t, filepath.Join(d, ".github/workflows/fuzz.yml"))
	if has := strings.Contains(b, triggerText); has == c.wantPushed {
		t.Fatalf("trigger present=%v after a run with pushed=%v", has, c.wantPushed)
	}
	return f, out
}

const (
	goodJobs = `{"jobs":[{"name":"fuzz (ubuntu-latest, amd64)","conclusion":"success"},{"name":"fuzz (ubuntu-24.04-arm, arm64)","conclusion":"success"}]}`
	goodLog  = "fuzz (ubuntu-latest, amd64)\tfuzz every target\t2026-11-17T12:00:00Z 4 targets: 4 PASS, 0 FAIL, 0 CRASH\n" +
		"fuzz (ubuntu-24.04-arm, arm64)\tfuzz every target\t2026-11-17T12:00:01Z 4 targets: 4 PASS, 0 FAIL, 0 CRASH\n"
)

func TestAdoptFinishHappyPath(t *testing.T) {
	f, _ := runFinish(t, finishCase{runSHA: testSHA, status: "completed", jobs: goodJobs, log: goodLog, wantCode: 0, wantPushed: true})
	if !f.called("git commit -a -m fuzz: remove the temporary push trigger") {
		t.Fatalf("no removal commit:\n%s", strings.Join(f.calls, "\n"))
	}
}

func TestAdoptFinishRefusesRedJob(t *testing.T) {
	red := strings.Replace(goodJobs, `"conclusion":"success"}]`, `"conclusion":"failure"}]`, 1)
	runFinish(t, finishCase{runSHA: testSHA, status: "completed", jobs: red, log: goodLog, wantCode: 2, wantInOut: ""})
}

func TestAdoptFinishRefusesMissingSummary(t *testing.T) {
	// the arm64 job's log has no summary line: green is not enough.
	onlyOne := strings.SplitAfter(goodLog, "\n")[0]
	runFinish(t, finishCase{runSHA: testSHA, status: "completed", jobs: goodJobs, log: onlyOne, wantCode: 2})
	// a summary where the passes do not add up to the targets.
	partial := strings.ReplaceAll(goodLog, "4 targets: 4 PASS, 0 FAIL", "4 targets: 3 PASS, 1 FAIL")
	runFinish(t, finishCase{runSHA: testSHA, status: "completed", jobs: goodJobs, log: partial, wantCode: 2})
}

func TestAdoptFinishRefusesWrongSHA(t *testing.T) {
	other := "ffffffffffffffffffffffffffffffffffffffff"
	runFinish(t, finishCase{runSHA: other, status: "completed", jobs: goodJobs, log: goodLog, wantCode: 2})
}

func TestAdoptFinishRefusesUnfinishedAndNoJobs(t *testing.T) {
	runFinish(t, finishCase{runSHA: testSHA, status: "in_progress", jobs: goodJobs, log: goodLog, wantCode: 2})
	runFinish(t, finishCase{runSHA: testSHA, status: "completed", jobs: `{"jobs":[]}`, log: goodLog, wantCode: 2})
}

func TestAdoptFinishCrash(t *testing.T) {
	log := goodLog + "fuzz (ubuntu-latest, amd64)\tfuzz every target\t2026-11-17T12:00:02Z CRASH ./sub FuzzB 1.2s sub/testdata/fuzz/FuzzB/abc\n" +
		"fuzz (ubuntu-latest, amd64)\tfuzz every target\t2026-11-17T12:00:03Z 4 targets: 3 PASS, 0 FAIL, 1 CRASH\n"
	runFinish(t, finishCase{runSHA: testSHA, status: "completed", jobs: goodJobs, log: log, wantCode: 1,
		wantInOut: "CRASH job \"fuzz (ubuntu-latest, amd64)\": ./sub FuzzB corpus sub/testdata/fuzz/FuzzB/abc"})
}

func TestAdoptFinishWrongBranchAndGitError(t *testing.T) {
	d := finishRepo(t)
	f := &fakeRunner{handler: func(tool string, a []string) (string, error) {
		if a[0] == "rev-parse" {
			return "main\n", nil
		}
		return "", nil
	}}
	withRunner(t, f)
	if _, _, code := execute(t, "adopt", "finish", "--dir", d); code != 2 || f.called("gitpush") {
		t.Fatalf("wrong branch: exit %d", code)
	}
	boom := &fakeRunner{handler: func(string, []string) (string, error) { return "", errors.New("boom") }}
	withRunner(t, boom)
	if _, _, code := execute(t, "adopt", "finish", "--dir", d); code != 2 {
		t.Fatalf("git error: exit %d", code)
	}
}

func TestTriggerRoundTrip(t *testing.T) {
	a, err := addTrigger(freshWorkflow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := addTrigger(a); err == nil {
		t.Fatal("a second trigger must be refused")
	}
	b, err := removeTrigger(a)
	if err != nil || b != freshWorkflow {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := removeTrigger(b); err == nil {
		t.Fatal("removing an absent trigger must be refused")
	}
}
