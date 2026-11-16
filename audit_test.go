package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The vendored subjects are real: go-simd/floats's nightly fuzz workflow before
// (floats-old) and after (floats-new) its PR #66, taken from git history, with
// the 18 FuzzXxx signatures of that repository.
const (
	subjOld = "testdata/audit/floats-old"
	subjNew = "testdata/audit/floats-new"
)

// cloneSubject copies a vendored subject so a test can mutate it.
func cloneSubject(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
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
	return dst
}

func TestAuditFloatsOld(t *testing.T) {
	out, _, code := execute(t, "audit", "--dir", subjOld)
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	// 9 targets are named by hand, but `-fuzz FuzzAxpy` matches FuzzAxpy and
	// FuzzAxpyRowsNoFMA and go test fuzzes neither: 8 covered, 10 gaps.
	if !strings.Contains(out, "audit: 18 targets, 10 without a workflow, 9 blanket continue-on-error") {
		t.Fatalf("summary wrong:\n%s", out)
	}
	for _, n := range []string{"FuzzMaxAbsMul", "FuzzCDotC", "FuzzCMulTwiddle", "FuzzConjReverse", "FuzzElem",
		"FuzzMDCTFold", "FuzzMulAddRows", "FuzzSquaredMagnitude", "FuzzAxpy:", "FuzzAxpyRowsNoFMA"} {
		if !strings.Contains(out, "GAP ./. "+n) {
			t.Errorf("missing GAP %s\n%s", n, out)
		}
	}
	for _, n := range []string{"FuzzDot:", "FuzzDistance:", "FuzzGather:", "FuzzRound:", "FuzzPairwise:", "FuzzSumPairwise:", "FuzzExtrema32:", "FuzzNoFMAKernels:"} {
		if strings.Contains(out, "GAP ./. "+n) {
			t.Errorf("%s is fuzzed by a step and must not be a gap\n%s", n, out)
		}
	}
	if !strings.Contains(out, "matches 2 targets") {
		t.Errorf("the ambiguous -fuzz FuzzAxpy is not explained\n%s", out)
	}
}

func TestAuditFloatsNew(t *testing.T) {
	out, _, code := execute(t, "audit", "--dir", subjNew)
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "audit: 18 targets, 0 without a workflow, 0 blanket continue-on-error") {
		t.Fatalf("summary wrong:\n%s", out)
	}
}

// Mutation: the same repository with the fuzzrun step replaced by nothing must
// go red, with every target a gap. If the gap check were blind to the step it
// would stay green on the old workflow too.
func TestAuditMutationFuzzrunStepRemoved(t *testing.T) {
	d := cloneSubject(t, subjNew)
	p := filepath.Join(d, ".github/workflows/fuzz.yml")
	b, _ := os.ReadFile(p)
	m := strings.Replace(string(b), "go run github.com/go-fleettools/fuzzrun@v0.2.0 run --time 3m", "echo skipped", 1)
	if m == string(b) {
		t.Fatal("mutation did not apply")
	}
	if err := os.WriteFile(p, []byte(m), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, code := execute(t, "audit", "--dir", d)
	if code != 1 || !strings.Contains(out, "audit: 18 targets, 18 without a workflow") {
		t.Fatalf("exit %d, the gap check stayed green:\n%s", code, out)
	}
}

// Mutation: dropping one explicit step from the old workflow makes exactly that
// target a gap.
func TestAuditMutationOneStepDropped(t *testing.T) {
	d := cloneSubject(t, subjOld)
	p := filepath.Join(d, ".github/workflows/fuzz.yml")
	b, _ := os.ReadFile(p)
	m := strings.Replace(string(b), "-fuzz FuzzRound ", "-fuzz FuzzNothing ", 1)
	if m == string(b) {
		t.Fatal("mutation did not apply")
	}
	if err := os.WriteFile(p, []byte(m), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, _ := execute(t, "audit", "--dir", d)
	if !strings.Contains(out, "GAP ./. FuzzRound: no workflow fuzzes it") || !strings.Contains(out, "11 without a workflow") {
		t.Fatalf("FuzzRound not reported:\n%s", out)
	}
}

func TestAuditRegexpAndShape(t *testing.T) {
	mk := func(run string, extra string) (string, int) {
		d := t.TempDir()
		write(t, filepath.Join(d, "go.mod"), "module m\n")
		write(t, filepath.Join(d, "a_test.go"), "package m\nimport \"testing\"\nfunc FuzzA(f *testing.F) {}\nfunc FuzzAB(f *testing.F) {}\nfunc FuzzC(f *testing.F) {}\n")
		write(t, filepath.Join(d, ".github/workflows/f.yml"), "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: "+run+"\n"+extra)
		out, _, code := execute(t, "audit", "--dir", d)
		return out, code
	}
	// anchored regexp selects one; unanchored FuzzA is ambiguous with FuzzAB.
	out, code := mk(`go test -run '^$' -fuzz '^FuzzA$' -fuzztime 1m ./...`, "")
	if code != 1 || !strings.Contains(out, "GAP ./. FuzzAB") || !strings.Contains(out, "GAP ./. FuzzC") || strings.Contains(out, "GAP ./. FuzzA:") {
		t.Fatalf("anchored: exit %d\n%s", code, out)
	}
	out, code = mk(`go test -fuzz=FuzzA ./...`, "")
	if code != 1 || !strings.Contains(out, "GAP ./. FuzzA: named but ambiguous") {
		t.Fatalf("ambiguous: exit %d\n%s", code, out)
	}
	// a regexp alternation covering all three is ambiguous too (go test fuzzes one target).
	out, code = mk(`go test -fuzz 'FuzzC|^FuzzA$' .`, "")
	if code != 1 || !strings.Contains(out, "GAP ./. FuzzAB") || strings.Contains(out, "GAP ./. FuzzC") {
		t.Fatalf("alternation: exit %d\n%s", code, out)
	}
	// fuzzrun anywhere in the script covers everything.
	out, code = mk("|\n          set +e\n          go run github.com/go-fleettools/fuzzrun@v0.2.0 run --time 3m", "")
	if code != 0 {
		t.Fatalf("fuzzrun: exit %d\n%s", code, out)
	}
	// a blanket continue-on-error on a fuzz step is reported even when covered.
	out, code = mk("go run github.com/go-fleettools/fuzzrun@v0.2.0 run", "        continue-on-error: true")
	if code != 1 || !strings.Contains(out, "BLANKET") || !strings.Contains(out, "0 without a workflow, 1 blanket") {
		t.Fatalf("blanket: exit %d\n%s", code, out)
	}
	// a step that does not fuzz is not a fuzz step.
	out, code = mk("go test ./...", "        continue-on-error: true")
	if code != 1 || strings.Contains(out, "BLANKET") || !strings.Contains(out, "3 without a workflow") {
		t.Fatalf("plain test: exit %d\n%s", code, out)
	}
}

func TestAuditMultiplePackagesRefused(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "go.mod"), "module m\n")
	write(t, filepath.Join(d, "a_test.go"), "package m\nimport \"testing\"\nfunc FuzzA(f *testing.F) {}\n")
	write(t, filepath.Join(d, "sub/b.go"), "package sub\n")
	write(t, filepath.Join(d, ".github/workflows/f.yml"), "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: go test -fuzz FuzzA ./...\n")
	out, _, code := execute(t, "audit", "--dir", d)
	if code != 1 || !strings.Contains(out, "multiple packages") || !strings.Contains(out, "GAP ./. FuzzA") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	// the same step naming the package is fine.
	write(t, filepath.Join(d, ".github/workflows/f.yml"), "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: go test -fuzz FuzzA .\n")
	if out, _, code = execute(t, "audit", "--dir", d); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestAuditExit2AndNoTargets(t *testing.T) {
	d := t.TempDir()
	if _, _, code := execute(t, "audit", "--dir", d); code != 2 {
		t.Fatalf("no go.mod: exit %d", code)
	}
	write(t, filepath.Join(d, "go.mod"), "module m\n")
	out, _, code := execute(t, "audit", "--dir", d)
	if code != 0 || !strings.Contains(out, "no fuzz targets") {
		t.Fatalf("no targets: exit %d\n%s", code, out)
	}
	write(t, filepath.Join(d, "a_test.go"), "package m\nimport \"testing\"\nfunc FuzzA(f *testing.F) {}\n")
	if _, _, code := execute(t, "audit", "--dir", d); code != 2 {
		t.Fatalf("no workflows: exit %d", code)
	}
	write(t, filepath.Join(d, ".github/workflows/f.yml"), "jobs: [unclosed\n  - : :\n")
	if _, _, code := execute(t, "audit", "--dir", d); code != 2 {
		t.Fatalf("bad yaml: exit %d", code)
	}
	write(t, filepath.Join(d, ".github/workflows/f.yml"), "on: push\n")
	write(t, filepath.Join(d, "b_test.go"), "package m\nfunc Fuzz( {\n")
	if _, _, code := execute(t, "audit", "--dir", d); code != 2 {
		t.Fatalf("bad go: exit %d", code)
	}
}

func TestCensus(t *testing.T) {
	root := t.TempDir()
	report := filepath.Join(t.TempDir(), "r.txt")
	for _, s := range []struct{ name, src string }{{"o/old", subjOld}, {"o/new", subjNew}} {
		d := cloneSubject(t, s.src)
		if err := os.MkdirAll(filepath.Join(root, "o"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(d, filepath.Join(root, s.name)); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(root, "o/plain/go.mod"), "module p\n")
	write(t, filepath.Join(root, "o/nowf/go.mod"), "module p\n")
	write(t, filepath.Join(root, "o/nowf/a_test.go"), "package p\nimport \"testing\"\nfunc FuzzA(f *testing.F) {}\n")
	out, _, code := execute(t, "census", "--root", root, "--report", report)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	want := "census: 4 directories; 3 audited, 1 unaudited (1 of them have fuzz targets but no workflow); 2 audited have fuzz targets, 1 with gaps, 1 with a blanket continue-on-error step"
	if !strings.Contains(out, want) {
		t.Fatalf("got %q", out)
	}
	b, _ := os.ReadFile(report)
	if !strings.Contains(string(b), "GAPS o/old 10/18") || !strings.Contains(string(b), "NOWORKFLOW o/nowf") {
		t.Fatalf("report:\n%s", b)
	}
	if _, _, code := execute(t, "census", "--root", t.TempDir()); code != 2 {
		t.Fatalf("empty root: exit %d", code)
	}
}
