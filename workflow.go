package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// fuzzrunVersion is the release the generated workflows run.
const fuzzrunVersion = "v0.9.0"

// fuzzStepText is the strict fuzz step: any non-zero exit fails the step, so
// a run that finds a crasher turns the workflow red.
const fuzzStepText = `      - name: fuzz every target (found by parsing, not listed)
        run: go run github.com/go-fleettools/fuzzrun@` + fuzzrunVersion + ` run --time 3m --jobs 2 --parallel 2 --logs fuzz-logs
`

const oldComment = `# Steps are continue-on-error so the benign deadline flake never reds this workflow;
# any real crasher is printed in the log and its input is uploaded as an artifact
# (add it under testdata/fuzz to turn it into a permanent ci.yml regression case).
`

const tolerantComment = `# The fuzz step tolerates fuzzrun's exit 1 (a crasher, or the benign deadline
# flake) so the flake never reds this workflow; any real crasher is printed in the
# summary and its input is uploaded as an artifact (add it under testdata/fuzz to
# turn it into a permanent ci.yml regression case). Exit 2, a run that could not
# be made, is red.
`

const redComment = `# A CRASHER IS RED. fuzzrun >= v0.7.0 gives the benign deadline its own verdict
# (DEADLINE, exit 0) and exits 1 only for a CRASH or an unexplained FAIL, exit 2
# when the run could not be made: every non-zero exit fails the step, and the
# crasher's input is uploaded as an artifact (add it under testdata/fuzz to turn
# it into a permanent ci.yml regression case). Before this the step tolerated
# exit 1, so a run that FOUND a crasher finished green.
`

const targetsComment = `# The targets are NOT listed here. fuzzrun finds every ` + "`func FuzzXxx(f *testing.F)`" + `
# by parsing the test files, so a new target is fuzzed without anyone remembering
# to add a step.
`

const newComment = redComment + "#\n" + targetsComment

// freshWorkflow is the nightly workflow of a repository that has none.
const freshWorkflow = `name: fuzz
# Nightly time-boxed randomized fuzzing. This deliberately does NOT run on pull
# requests: ` + "`go test -fuzz`" + ` is wall-clock time-boxed and the Go fuzzing engine
# intermittently exits non-zero with "context deadline exceeded" when a worker does
# not wind down within -fuzztime even though no crasher was found, which made it a
# false-red PR gate. The deterministic seed-corpus run stays in ci.yml (blocking).
#
` + newComment + `on:
  schedule:
    - cron: '0 3 * * *'
  workflow_dispatch:
jobs:
  fuzz:
    strategy:
      fail-fast: false
      matrix:
        include:
          - { os: ubuntu-latest, arch: amd64 }
          - { os: ubuntu-24.04-arm, arch: arm64 }
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-go@v7
        with: { go-version: '1.27.4' }
` + fuzzStepText + `      - name: upload the crasher
        if: failure()
        uses: actions/upload-artifact@v7
        with:
          name: fuzz-crashers-${{ matrix.arch }}
          path: testdata/fuzz/
          if-no-files-found: ignore
      - name: upload the per-target logs
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: fuzz-logs-${{ matrix.arch }}
          path: fuzz-logs/
          if-no-files-found: ignore
`

var (
	goTestFuzzRun = regexp.MustCompile(`(?s)^\s*go test\b.*-fuzz`)
	oldGoVersion  = regexp.MustCompile(`go-version: '1\.27\.[0-3]'`)
)

func stepField(st *yaml.Node, key string) string {
	for k := 0; st.Kind == yaml.MappingNode && k+1 < len(st.Content); k += 2 {
		if st.Content[k].Value == key {
			return st.Content[k+1].Value
		}
	}
	return ""
}

func isGoTestFuzz(st *yaml.Node) bool { return goTestFuzzRun.MatchString(stepField(st, "run")) }

func isTolerantFuzzrun(st *yaml.Node) bool {
	run := stepField(st, "run")
	return strings.Contains(run, "fuzzrun") && strings.Contains(run, "-ge 2")
}

// rewriteWorkflow turns every job of src that fuzzes with one `go test -fuzz`
// step per target, or with earlier versions' exit-1-tolerant step, into the
// strict fuzzrun form. It returns the new text and the number of steps
// replaced (0: nothing to do). The jobs are found by parsing the YAML, under
// the top-level `jobs:` key only; `gotip test` steps are left alone.
func rewriteWorkflow(src string) (string, int, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		return "", 0, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return "", 0, errors.New("not a workflow: the document is not a mapping")
	}
	var jobs *yaml.Node
	top := doc.Content[0]
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value == "jobs" {
			jobs = top.Content[i+1]
		}
	}
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return "", 0, errors.New("no top-level jobs: mapping")
	}
	lines := strings.SplitAfter(src, "\n")
	type edit struct {
		end  int
		text string
	}
	edits := map[int]edit{}
	replaced := 0
	for ji := 0; ji+1 < len(jobs.Content); ji += 2 {
		job := jobs.Content[ji+1]
		jobEnd := len(lines)
		if ji+2 < len(jobs.Content) {
			jobEnd = jobs.Content[ji+2].Line - 1
		}
		var steps *yaml.Node
		for k := 0; job.Kind == yaml.MappingNode && k+1 < len(job.Content); k += 2 {
			if job.Content[k].Value == "steps" {
				steps = job.Content[k+1]
			}
		}
		if steps == nil || steps.Kind != yaml.SequenceNode || len(steps.Content) == 0 {
			continue
		}
		type blk struct {
			start, end int
			node       *yaml.Node
		}
		var bs []blk
		anyFuzz := false
		for si, st := range steps.Content {
			start := st.Line - 1
			if isTolerantFuzzrun(st) {
				prevEnd := 0
				if si > 0 {
					prevEnd = bs[si-1].end
				}
				for start > prevEnd && (strings.TrimSpace(lines[start-1]) == "" || strings.HasPrefix(strings.TrimSpace(lines[start-1]), "#")) {
					start--
				}
			}
			end := jobEnd
			if si+1 < len(steps.Content) {
				end = steps.Content[si+1].Line - 1
			}
			// blank lines and comments before the next step belong to it.
			for end > st.Line && (strings.TrimSpace(lines[end-1]) == "" || strings.HasPrefix(strings.TrimSpace(lines[end-1]), "#")) {
				end--
			}
			bs = append(bs, blk{start, end, st})
			if isGoTestFuzz(st) || isTolerantFuzzrun(st) {
				anyFuzz = true
			}
		}
		if !anyFuzz {
			continue
		}
		haveLogs := strings.Contains(strings.Join(lines[bs[0].start:jobEnd], ""), "fuzz-logs")
		inserted := false
		for _, b := range bs {
			switch {
			case isGoTestFuzz(b.node) || isTolerantFuzzrun(b.node):
				replaced++
				txt := ""
				if !inserted {
					txt, inserted = fuzzStepText, true
				}
				edits[b.start] = edit{b.end, txt}
			case !haveLogs && stepField(b.node, "name") == "upload any fuzz-discovered corpus":
				block := strings.Join(lines[b.start:b.end], "")
				crasher := strings.NewReplacer(
					"upload any fuzz-discovered corpus", "upload the crasher",
					"if: always()", "if: failure()",
					"fuzz-findings", "fuzz-crashers",
				).Replace(block)
				logs := strings.NewReplacer(
					"upload any fuzz-discovered corpus", "upload the per-target logs",
					"fuzz-findings", "fuzz-logs",
					"testdata/fuzz/", "fuzz-logs/",
				).Replace(block)
				edits[b.start] = edit{b.end, crasher + logs}
			case haveLogs && stepField(b.node, "name") == "upload any fuzz-discovered corpus":
				block := strings.Join(lines[b.start:b.end], "")
				crasher := strings.NewReplacer(
					"upload any fuzz-discovered corpus", "upload the crasher",
					"if: always()", "if: failure()",
					"fuzz-findings", "fuzz-crashers",
				).Replace(block)
				edits[b.start] = edit{b.end, crasher}
			}
		}
		for i := bs[0].start; i < jobEnd; i++ {
			if m := oldGoVersion.FindString(lines[i]); m != "" {
				lines[i] = strings.Replace(lines[i], m, "go-version: '1.27.4'", 1)
			}
		}
	}
	if replaced == 0 {
		return src, 0, nil
	}
	var sb strings.Builder
	for i := 0; i < len(lines); {
		if e, ok := edits[i]; ok {
			sb.WriteString(e.text)
			i = e.end
			continue
		}
		sb.WriteString(lines[i])
		i++
	}
	res := sb.String()
	res = strings.Replace(res, oldComment, newComment, 1)
	res = strings.Replace(res, tolerantComment, redComment, 1)
	return res, replaced, nil
}

func workflowCmd() *cobra.Command {
	var dir string
	var write bool
	cmd := &cobra.Command{
		Use:   "workflow",
		Short: "Rewrite the nightly fuzz workflow to run fuzzrun (or create it)",
		Long: `Rewrites .github/workflows/fuzz.yml so that every job fuzzing with one
"go test -fuzz" step per target runs "fuzzrun run" instead: the targets are found
by parsing, any crasher fails the step (non-zero exit), the crasher is uploaded
on failure, and the per-target logs are uploaded. Jobs are found by parsing the
YAML under the top-level jobs key; "gotip test" steps are left alone. When
there is no fuzz.yml, a nightly one is created.

Without --write, says what would change and writes nothing.

Exit status: 0 changed (or would change), 1 nothing to change, 2 could not.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			if !isModule(dir) {
				return &exitError{2, fmt.Errorf("no go.mod in %s", dir)}
			}
			ts, err := discover(dir, nil)
			if err != nil {
				return &exitError{2, err}
			}
			if len(ts) == 0 {
				return &exitError{2, errors.New("no fuzz targets found")}
			}
			path := filepath.Join(dir, ".github", "workflows", "fuzz.yml")
			b, err := os.ReadFile(path)
			var res string
			switch {
			case errors.Is(err, os.ErrNotExist):
				res = freshWorkflow
				fmt.Fprintf(out, "create %s (%d targets)\n", path, len(ts))
			case err != nil:
				return &exitError{2, err}
			default:
				var n int
				res, n, err = rewriteWorkflow(string(b))
				if err != nil {
					return &exitError{2, fmt.Errorf("%s: %w", path, err)}
				}
				if n == 0 {
					fmt.Fprintf(out, "%s: no go test -fuzz step to replace\n", path)
					return &exitError{code: 1}
				}
				fmt.Fprintf(out, "rewrite %s: %d steps replaced by one fuzzrun step (%d targets)\n", path, n, len(ts))
			}
			if !write {
				return nil
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return &exitError{2, err}
			}
			if err := os.WriteFile(path, []byte(res), 0o644); err != nil {
				return &exitError{2, err}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", ".", "module root")
	cmd.Flags().BoolVar(&write, "write", false, "write the file (default: only say what would change)")
	return cmd
}
