package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// What `go test -fuzz` prints when the coordinator's deadline arrives while a
// worker is still inside an input, with nothing found. The signature is the one
// go-crdt/crdt's hostile lane greps for to downgrade it to a warning.
const deadlineOut = `fuzz: elapsed: 30s, execs: 812345 (27078/sec), new interesting: 3 (total: 41)
--- FAIL: FuzzHostileTree (30.41s)
    fuzzing process hung or terminated unexpectedly: context deadline exceeded
FAIL
exit status 1
FAIL	example.com/m/structured	30.452s
`

// A target that wrote a failing input and THEN ran into the deadline: both
// strings are in its output.
const crashThenDeadline = `--- FAIL: FuzzDecode (12.03s)
    --- FAIL: FuzzDecode (0.00s)
        decode_test.go:40: index out of range
    Failing input written to testdata/fuzz/FuzzDecode/9f3c2a
    To re-run:
    go test -run=FuzzDecode/9f3c2a
    context deadline exceeded
FAIL
`

const plainFail = `--- FAIL: FuzzSeed (0.00s)
    seed_test.go:12: the seed corpus itself fails
FAIL
`

func TestClassifySeparatesTheDeadlineFromACrash(t *testing.T) {
	for _, c := range []struct {
		name, out string
		want      verdict
	}{
		{"the benign deadline", deadlineOut, vDeadline},
		// ⛔ The order is the point: the crasher decides, whatever else the
		// output says. A classifier that looked for the deadline first would
		// turn a real crash into a warning.
		{"a crasher that also hit the deadline", crashThenDeadline, vCrash},
		{"a plain failure", plainFail, vFail},
	} {
		got, corpus := classify(c.out, "./structured")
		if got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
		if c.want == vCrash && corpus != "structured/testdata/fuzz/FuzzDecode/9f3c2a" {
			t.Errorf("%s: corpus %q", c.name, corpus)
		}
		if c.want != vCrash && corpus != "" {
			t.Errorf("%s: a %s carries a corpus %q", c.name, got, corpus)
		}
	}
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var e *exitError
	if errors.As(err, &e) {
		return e.code
	}
	return -1
}

// ⛔ The whole reason for the verdict: a deadline must NOT make the run exit 1,
// and a crash or a failure still must -- otherwise a lane can only honour exit
// 1 and go red on weather, or tolerate it and go green on a crash.
func TestOnlyAFailOrACrashExitsOne(t *testing.T) {
	tg := func(n string) target { return target{pkg: "./structured", name: n} }
	for _, c := range []struct {
		name string
		rs   []result
		want int
	}{
		{"pass and deadline", []result{{t: tg("FuzzA"), v: vPass}, {t: tg("FuzzB"), v: vDeadline}}, 0},
		{"a deadline beside a crash", []result{{t: tg("FuzzA"), v: vDeadline}, {t: tg("FuzzB"), v: vCrash, corpus: "x"}}, 1},
		{"a deadline beside a failure", []result{{t: tg("FuzzA"), v: vDeadline}, {t: tg("FuzzB"), v: vFail}}, 1},
	} {
		var out bytes.Buffer
		if got := exitCodeOf(summarize(&out, c.rs)); got != c.want {
			t.Errorf("%s: exit %d, want %d\n%s", c.name, got, c.want, out.String())
		}
	}
}

// The deadline is printed and counted, never silent.
func TestTheDeadlineIsCountedAndNamed(t *testing.T) {
	var out bytes.Buffer
	_ = summarize(&out, []result{
		{t: target{pkg: "./structured", name: "FuzzA"}, v: vPass},
		{t: target{pkg: "./structured", name: "FuzzB"}, v: vDeadline, note: "exit status 1", log: "b.log"},
	})
	s := out.String()
	if !strings.Contains(s, "2 targets: 1 PASS, 0 FAIL, 0 CRASH, 1 DEADLINE") {
		t.Errorf("summary line wrong:\n%s", s)
	}
	if !strings.Contains(s, "DEADLINE ./structured FuzzB") || !strings.Contains(s, "log b.log") {
		t.Errorf("the deadline target is not named with its log:\n%s", s)
	}
}

// ⛔ THE COMPATIBILITY PROMISE, held against adopt's OWN regex rather than a
// copy of it: the suffix must not stop `adopt` reading the line, and a
// deadline must read there as 0 FAIL, which is what makes its gate more
// accurate rather than less.
func TestAdoptStillReadsTheSummary(t *testing.T) {
	var out bytes.Buffer
	_ = summarize(&out, []result{
		{t: target{pkg: "./.", name: "FuzzA"}, v: vPass},
		{t: target{pkg: "./.", name: "FuzzB"}, v: vDeadline},
	})
	m := summaryRe.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("adopt's summaryRe no longer matches:\n%s", out.String())
	}
	if m[1] != "2" || m[2] != "1" || m[3] != "0" || m[4] != "0" {
		t.Errorf("adopt reads targets=%s pass=%s fail=%s crash=%s, want 2 1 0 0", m[1], m[2], m[3], m[4])
	}
}
