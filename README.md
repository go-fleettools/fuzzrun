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
  line is a `CRASH`, and the summary gives that path relative to the module. Any
  other failing exit is a `FAIL` with the log to read.

Summary:

```text
PASS  ./. FuzzGood 5s
CRASH ./. FuzzBad  1.2s testdata/fuzz/FuzzBad/6f1c...
2 targets: 1 PASS, 0 FAIL, 1 CRASH
```

Exit status: `0` every target passed, `1` at least one `FAIL` or `CRASH`,
`2` the run could not be made (no `go.mod`, no targets, `go` missing, bad flags,
unreadable load with `--max-load`).

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
`--package`). Otherwise only a `go test -fuzz` that go test would really run
counts: the pattern is an unanchored regexp, a pattern matching more than one
target of the package fuzzes none, and `-fuzz` with several packages (`./...` over
a multi-package module) is refused by the go tool. Those steps are reported as
`NOTE`s and their targets stay gaps.

`${{ matrix.KEY }}` in a `-fuzz` pattern is expanded from the job's
`strategy.matrix` (list values and `include` entries). A step the audit cannot
read (a pattern computed by the shell, `make fuzz`, a script, a
`working-directory`) makes the uncovered targets `UNCERTAIN` instead of `GAP`;
they do not fail the audit.

Exit status: `0` everything covered or uncertain (a repository with no targets is `0` with a
note), `1` gaps or a blanket `continue-on-error`, `2` nothing could be read (no
`go.mod`, no workflows, a parse error).

`fuzzrun census --root <dir> [--report file]` runs the audit over every
`<dir>/<org>/<repo>` clone (the layout of `gorequires --clone-dir`) and writes a
report with the counts.

## `fuzzrun workflow`

```sh
fuzzrun workflow --dir <repo> [--write]
```

Rewrites `.github/workflows/fuzz.yml` into the form of go-simd/floats#66: every
job fuzzing with one `go test -fuzz` step per target gets one `fuzzrun run` step
(exit 2 red, exit 1 tolerated) and a per-target logs artifact. Jobs are found by
parsing the YAML under the top-level `jobs:` key; `gotip test` steps are left
alone. With no `fuzz.yml`, a nightly one is created. Without `--write` it only
says what would change. Exit `0` changed, `1` nothing to change, `2` could not.

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
