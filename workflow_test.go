package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// decoded parses a workflow, with the fuzzrun version normalised (floats#66
// pinned v0.2.0, the generator pins the current release).
func decoded(t *testing.T, s string) any {
	t.Helper()
	s = strings.NewReplacer("fuzzrun@v0.2.0", "fuzzrun@V", "fuzzrun@"+fuzzrunVersion, "fuzzrun@V").Replace(s)
	var v any
	if err := yaml.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// go-simd/floats's fuzz.yml before #66 must become the strict fuzzrun workflow.
func TestRewriteFloatsOldIsNew(t *testing.T) {
	old := readFile(t, "testdata/audit/floats-old/.github/workflows/fuzz.yml")
	want := readFile(t, "testdata/audit/floats-new/.github/workflows/fuzz.yml")
	got, n, err := rewriteWorkflow(old)
	if err != nil || n != 9 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if !reflect.DeepEqual(decoded(t, got), decoded(t, want)) {
		t.Fatalf("rewrite differs from floats#66:\n%s", got)
	}
	// idempotent: the new form has nothing left to replace.
	if again, n, _ := rewriteWorkflow(got); n != 0 || again != got {
		t.Fatalf("not idempotent: n=%d", n)
	}
}

// A tolerant workflow written by earlier fuzzrun versions is rewritten to the strict form.
func TestRewriteTolerantWorkflow(t *testing.T) {
	old := readFile(t, "testdata/workflow/tolerant.yml")
	want := readFile(t, "testdata/audit/floats-new/.github/workflows/fuzz.yml")
	got, n, err := rewriteWorkflow(old)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if strings.Contains(got, "-ge 2") || strings.Contains(got, "set +e") {
		t.Fatalf("tolerant form survived:\n%s", got)
	}
	if !strings.Contains(got, "upload the crasher") || !strings.Contains(got, "fuzz-crashers-") {
		t.Fatalf("missing crasher upload:\n%s", got)
	}
	if !reflect.DeepEqual(decoded(t, got), decoded(t, want)) {
		t.Fatalf("rewrite differs from want:\n%s", got)
	}
	// idempotent:
	if again, n, _ := rewriteWorkflow(got); n != 0 || again != got {
		t.Fatalf("not idempotent: n=%d", n)
	}
}

// adler32 has a second job on gotip: it must be left alone.
func TestRewriteLeavesGotipJob(t *testing.T) {
	src := readFile(t, "testdata/workflow/adler32.yml")
	got, n, err := rewriteWorkflow(src)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	for _, w := range []string{"fuzzrun@" + fuzzrunVersion + " run", "fuzz-logs-${{ matrix.arch }}", "gotip test -run '^$' -fuzz FuzzChecksum"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q\n%s", w, got)
		}
	}
	if strings.Count(got, "go-version: '1.27.3'") != 1 || strings.Count(got, "go-version: '1.27.4'") != 1 {
		t.Errorf("only the first job's Go version moves:\n%s", got)
	}
	if strings.Contains(got, "go test -run") {
		t.Errorf("a go test step survived\n%s", got)
	}
}

// Mutation proving the job tracking: a go test -fuzz step in the second job
// is rewritten too, and a key named like a job outside jobs: is not a job.
func TestRewriteJobTrackingMutation(t *testing.T) {
	src := readFile(t, "testdata/workflow/adler32.yml")
	m := strings.Replace(src, "run: gotip test -run", "run: go test -run", 1)
	if m == src {
		t.Fatal("mutation did not apply")
	}
	_, n, err := rewriteWorkflow(m)
	if err != nil || n != 2 {
		t.Fatalf("both jobs must be rewritten: n=%d err=%v", n, err)
	}
	// Renaming the jobs key: no top-level jobs, a refusal and not a silent no-op.
	if _, _, err := rewriteWorkflow(strings.Replace(src, "\njobs:\n", "\njobz:\n", 1)); err == nil {
		t.Fatal("no jobs: key must be an error")
	}
	// A fuzz command under on: (not a job) is not touched.
	only := "on:\n  workflow_dispatch:\n    inputs:\n      x:\n        default: go test -fuzz A\njobs:\n  a:\n    steps:\n      - run: echo hi\n"
	if _, n, err := rewriteWorkflow(only); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestWorkflowCmd(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "go.mod"), "module m\n")
	if _, _, code := execute(t, "workflow", "--dir", d); code != 2 {
		t.Fatalf("no targets: exit %d", code)
	}
	write(t, filepath.Join(d, "a_test.go"), "package m\nimport \"testing\"\nfunc FuzzA(f *testing.F) {}\n")
	out, _, code := execute(t, "workflow", "--dir", d)
	if code != 0 || !strings.Contains(out, "create") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(d, ".github/workflows/fuzz.yml")); err == nil {
		t.Fatal("written without --write")
	}
	if _, _, code = execute(t, "workflow", "--dir", d, "--write"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	// the created workflow is covered by the audit, and has nothing left to rewrite.
	if out, _, code = execute(t, "audit", "--dir", d); code != 0 {
		t.Fatalf("audit exit %d\n%s", code, out)
	}
	if _, _, code = execute(t, "workflow", "--dir", d, "--write"); code != 1 {
		t.Fatalf("second run: exit %d", code)
	}
	// an existing hand-written fuzz.yml is rewritten.
	e := cloneSubject(t, "testdata/audit/floats-old")
	if out, _, code = execute(t, "workflow", "--dir", e, "--write"); code != 0 || !strings.Contains(out, "9 steps replaced") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if out, _, code = execute(t, "audit", "--dir", e); code != 0 {
		t.Fatalf("audit after rewrite: exit %d\n%s", code, out)
	}
}
