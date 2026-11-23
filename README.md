# fuzzrun

Run every Go fuzz target of a module, in parallel within a load budget, and
report crashers.

`go test -fuzz` runs one target of one package at a time. A module with thirty
targets needs thirty commands, and a run left unattended either overloads the
machine or leaves it idle. `fuzzrun` finds the targets, runs a few at once,
waits for the machine to be quiet enough before starting each one, keeps one log
per target, and says in a summary which target crashed and where the corpus file
that reproduces it was written.

## Install

```sh
GOBIN=~/.local/bin go install github.com/go-fleettools/fuzzrun@latest
```

## `fuzzrun run`

```sh
fuzzrun run [--dir .] [--time 10m] [--jobs 3] [--parallel 2] \
            [--max-load 0] [--logs DIR] [--package pattern...]
```

- Targets are found by parsing the `*_test.go` files (`go/parser`, not a regexp):
  top-level `func FuzzXxx(f *testing.F)`. `.git` and `testdata` are skipped. A
  test file that does not parse is an error, never silently zero targets.
- Each target runs as `go test -run=^$ -fuzz=^Name$ -fuzztime=D -parallel=P ./pkg`
  with `GOWORK=off`, at most `--jobs` at a time, output in
  `<logs>/<pkg>-<Name>.log` (default: a new temporary directory, printed).
- `--max-load L` (L > 0): before starting each target, wait while the 1-minute
  load average is above L. It is read from `sysctl vm.loadavg` on darwin and
  `/proc/loadavg` on linux. Where it cannot be read, `run` exits 2 up front
  instead of pretending the machine was quiet.
- `--package` keeps only matching packages (`path.Match` on the module-relative
  directory, or `dir/...` for a subtree); repeatable.
- A target that fails with a `Failing input written to testdata/fuzz/<Name>/<hash>`
  line is a `CRASH`, and the summary gives that path relative to the module.
- A target that fails with `context deadline exceeded` and wrote **no** failing
  input is a `DEADLINE`: the fuzz coordinator's own deadline arrived while a
  worker was still inside an input, with nothing found. It is printed with its
  log and counted, and it does **not** make the run exit 1. ⛔ The crasher is
  checked first: a target can reach the deadline after writing a failing input,
  its output then holds both strings, and it is a `CRASH`.
- Any other failing exit is a `FAIL` with the log to read.

Summary:

```text
PASS     ./. FuzzGood 5s
CRASH    ./. FuzzBad  1.2s testdata/fuzz/FuzzBad/6f1c...
DEADLINE ./. FuzzSlow 30.4s (exit status 1; log …/root-FuzzSlow.log)
3 targets: 1 PASS, 0 FAIL, 1 CRASH, 1 DEADLINE
```

Exit status: `0` every target passed or reached the deadline, `1` at least one
`FAIL` or `CRASH`, `2` the run could not be made (no `go.mod`, no targets, `go`
missing, bad flags, unreadable load with `--max-load`).

⛔ **Why the deadline has a verdict of its own.** Until v0.7.0 it was a `FAIL`, so
exit 1 could not tell a crash from weather, and the workflow `fuzzrun workflow`
writes had to tolerate exit 1 — which keeps a lane green on the benign deadline
**and on a real crasher**, visible then only in the log. A lane that wants
"a crash is red, a deadline warns" had to keep its own shell loop: go-crdt/crdt's
hostile lane does exactly that (go-crdt/crdt#184), and could not move to `run`
without losing it. The `DEADLINE` count is appended after `CRASH` rather than
inserted, so `adopt`'s parser of this line keeps reading it, and a deadline now
reads there as `0 FAIL` instead of masquerading as one.

## `fuzzrun wait`

```sh
fuzzrun wait FILE SUBSTRING [--timeout 10m] [--interval 2s]
```

Blocks until FILE contains SUBSTRING, for example a log written by a background
`fuzzrun run`. Prints `found` (exit `0`) or `timeout` (exit `1`); exit `2` on a
read error other than the file not existing yet.

## `fuzzrun audit`

```sh
fuzzrun audit --dir <repo>
```

Finds the fuzz targets no workflow fuzzes. It parses the test files for the
`FuzzXxx` targets (as `run` does), reads `.github/workflows/*.yml` and prints a
`GAP` line per target that no step fuzzes, and a `BLANKET` line per fuzz step
under `continue-on-error: true` (a step that cannot fail cannot say that nothing
was fuzzed). A step running `fuzzrun run` covers every target (or those of its
`--package`); the program is any shell word whose last path element is
`fuzzrun`, quoted or not — `fuzzrun`, `"$(go env GOPATH)/bin/fuzzrun"`,
`go run github.com/go-fleettools/fuzzrun@vX run` — while `echo "fuzzrun run"`,
a `# … fuzzrun run` comment or `xfuzzrun run` are not calls. Otherwise only a `go test -fuzz` that go test would really run
counts: the pattern is an unanchored regexp, a pattern matching more than one
target of the package fuzzes none, and `-fuzz` with several packages (`./...` over
a multi-package module) is refused by the go tool. Those steps are reported as
`NOTE`s and their targets stay gaps.

`${{ matrix.KEY }}` is expanded from the job's `strategy.matrix` **anywhere in
the step's script** — the `-fuzz` pattern, the package operand, both — because a
matrix lane names them together: `-fuzz '^${{ matrix.target }}$' ${{ matrix.pkg }}`.
Expanding only the pattern left the package literal, so the step read as
computed at run time and every target it covers came out `UNCERTAIN`: measured
on go-crdt/crdt, **35 targets, 35 uncertain, exit 0** — a lane green while
deciding nothing, over a matrix written out in full in the file. With the
package expanded the same repository reports 20 covered and 15 uncertain, the
15 being a lane whose pattern a shell loop builds.

⛔ The combinations are **paired, not crossed**. The list keys give the cross
product, `exclude` removes what it matches, and each `include` entry is a job of
its own — so twenty `include` entries pairing a package with a target stay
twenty jobs rather than becoming sixty. Coverage is keyed by (package, target),
so an invented job could mark a target covered when the same target name exists
in the other package, and a false "covered" is the one answer an audit must not
produce. A matrix holding **both** a list and `include` is not a pairing this
reads: the two are crossed and the report says so in a `NOTE`.

A step the audit cannot read (a pattern computed by the shell, `make fuzz`, a
script, a `working-directory`) makes the uncovered targets `UNCERTAIN` instead
of `GAP`; they do not fail the audit — unless **every** target is uncertain.
Then the audit decided nothing, and that is exit `2`, not the `0` it gave before
v0.8.0: an answer not obtained is not a negative.

Exit status: `0` everything covered, or some covered and the rest uncertain (a
repository with no targets is `0` with a note), `1` gaps or a blanket
`continue-on-error`, `2` nothing could be read (no `go.mod`, no workflows, a
parse error, or every target uncertain).

`fuzzrun census --root <dir> [--report file]` runs the audit over every
`<dir>/<org>/<repo>` clone (the layout of `gorequires --clone-dir`) and writes a
report with the counts.

## `fuzzrun workflow`

```sh
fuzzrun workflow --dir <repo> [--write]
```

Rewrites `.github/workflows/fuzz.yml`: every job fuzzing with one `go test -fuzz`
step per target gets one `fuzzrun run` step (fails on any crasher, crasher uploaded
on failure) and a per-target logs artifact. Jobs are found by
parsing the YAML under the top-level `jobs:` key; `gotip test` steps are left
alone. With no `fuzz.yml`, a nightly one is created. Without `--write` it only
says what would change. Exit `0` changed, `1` nothing to change, `2` could not.

## `fuzzrun adopt`

```sh
fuzzrun adopt open   --dir <clone>
fuzzrun adopt finish --dir <clone>
```

`open` branches `fuzzrun-workflow` from `origin/HEAD`, runs the `workflow`
rewrite, commits it, adds a temporary `push` trigger in a second commit, pushes
with `gitpush` and opens the pull request with `gh pr create`; it prints the URL.
Once the run on the branch has finished, `finish` reads the latest push run of
`fuzz.yml` for the SHA of the branch head (`git rev-parse`) and refuses (exit
`2`) unless every job concluded success and every job log carries
`N targets: N PASS, 0 FAIL, 0 CRASH`. A crasher is printed and exits `1`.
Otherwise the trigger is removed, committed and pushed (exit `0`); merging stays
with `prwait` and `ghmerge`.

## `fuzzrun seedcorpus`

```sh
fuzzrun run --time 20s          # fills the Go fuzz cache
fuzzrun seedcorpus [--dir .] [--cache DIR] [--max 40] [--max-bytes 65536]
```

Copies the inputs the fuzz engine cached (`$GOCACHE/fuzz/<module path>`, which
`go test -fuzz` fills; only crashers are written under `testdata/fuzz`) into
`testdata/fuzz/<Target>/`: per target the `--max` smallest files, none over
`--max-bytes`. The corpus stays small and holds inputs only, so the blocking CI
run replays what a nightly run would otherwise rediscover.

## `fuzzrun scan`

```sh
fuzzrun scan --org ORG REPO...
```

Reads `.github/workflows/fuzz.yml` of each repo from raw.githubusercontent.com
(no REST budget) and prints `fuzzrun=… tolerant=… continue-on-error=…`.
`tolerant` is the exit-1 tolerance (`-ge 2`) written by `fuzzrun workflow`
before v0.8.0, which lets a crasher finish green (#23). A file that could not
be read is `NOT READ`, never an absence. Exit 1 when a repo is tolerant or not
read.

## Why

The fuzz targets of a module are a security control only if they are actually
run, all of them, for long enough, without taking the machine down. This tool
came out of the go-llmflow/gateway security audit, where thirty targets were
run by hand with a shell loop that could not tell a crash from a timeout.

The tests plant a failing target (`testdata/planted`) and require `run` to report
it with its corpus path and exit 1; CI does the same through the built binary.
The module is copied to a temporary directory first, so the corpus a crash
writes never lands in the repository.

## Development

```sh
go vet ./... && go test -race ./...
```

Fleet CLI shape: cobra, `RootCmd()` driven by tests with `SetArgs`/`SetOut`/
`SetErr`, an `osExit` variable. Releases are semver tags.
