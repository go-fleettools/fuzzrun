package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

// RootCmd builds the command tree. Tests drive it with SetArgs/SetOut/SetErr.
func RootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "fuzzrun",
		Short:         "Run every Go fuzz target of a module and report crashers",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(runCmd(), waitCmd())
	return root
}

type verdict string

const (
	vPass  verdict = "PASS"
	vFail  verdict = "FAIL"
	vCrash verdict = "CRASH"
)

type result struct {
	t      target
	v      verdict
	dur    time.Duration
	corpus string // module-relative path of the crasher, when known
	log    string
	note   string
}

var failingInput = regexp.MustCompile(`Failing input written to (\S+)`)

// parseCrasher finds the "Failing input written to testdata/fuzz/<Name>/<hash>"
// line the go tool prints, and returns the path joined onto pkg (the package
// directory relative to the module, "./sub" or "./.").
func parseCrasher(output, pkg string) (string, bool) {
	m := failingInput.FindStringSubmatch(output)
	if m == nil {
		return "", false
	}
	return path.Join(strings.TrimPrefix(pkg, "./"), filepath.ToSlash(m[1])), true
}

func runCmd() *cobra.Command {
	var (
		dir      string
		fuzzTime string
		jobs     int
		parallel int
		maxLoad  float64
		logs     string
		pkgs     []string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Fuzz every target of the module at --dir",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			if jobs < 1 || parallel < 1 {
				return &exitError{2, errors.New("--jobs and --parallel must be at least 1")}
			}
			if _, err := time.ParseDuration(fuzzTime); err != nil {
				// -fuzztime also accepts "100x" (an execution count).
				if !regexp.MustCompile(`^[0-9]+x$`).MatchString(fuzzTime) {
					return &exitError{2, fmt.Errorf("--time %q: %w", fuzzTime, err)}
				}
			}
			if !isModule(dir) {
				return &exitError{2, fmt.Errorf("no go.mod in %s", dir)}
			}
			if _, err := exec.LookPath("go"); err != nil {
				return &exitError{2, fmt.Errorf("go not found: %w", err)}
			}
			if maxLoad > 0 {
				if _, err := loadAvg(); err != nil {
					return &exitError{2, fmt.Errorf("--max-load given but the load average cannot be read: %w", err)}
				}
			}
			ts, err := discover(dir, pkgs)
			if err != nil {
				return &exitError{2, err}
			}
			if len(ts) == 0 {
				return &exitError{2, errors.New("no fuzz targets found")}
			}
			if logs == "" {
				if logs, err = os.MkdirTemp("", "fuzzrun-"); err != nil {
					return &exitError{2, err}
				}
			} else if err := os.MkdirAll(logs, 0o755); err != nil {
				return &exitError{2, err}
			}
			fmt.Fprintf(out, "%d targets, %d at a time, logs in %s\n", len(ts), jobs, logs)

			results := runAll(out, cmd.ErrOrStderr(), dir, logs, ts, fuzzTime, jobs, parallel, maxLoad)
			return summarize(out, results)
		},
	}
	f := cmd.Flags()
	f.StringVar(&dir, "dir", ".", "module root")
	f.StringVar(&fuzzTime, "time", "10m", "fuzztime per target")
	f.IntVar(&jobs, "jobs", 3, "targets run at once")
	f.IntVar(&parallel, "parallel", 2, "fuzzing workers per target (go test -parallel)")
	f.Float64Var(&maxLoad, "max-load", 0, "before starting a target, wait while the 1-minute load average is above this (0 disables)")
	f.StringVar(&logs, "logs", "", "directory for the per-target logs (default: a new temporary directory)")
	f.StringSliceVar(&pkgs, "package", nil, "only fuzz targets in matching packages (path.Match, or dir/...); repeatable")
	return cmd
}

// loadPoll is how often a target waiting for the load to drop looks again.
var loadPoll = 5 * time.Second

func runAll(out, errw io.Writer, dir, logs string, ts []target, fuzzTime string, jobs, parallel int, maxLoad float64) []result {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []result
		queue   = make(chan target)
	)
	for i := 0; i < jobs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range queue {
				if maxLoad > 0 {
					waitForLoad(errw, &mu, t, maxLoad)
				}
				r := runOne(dir, logs, t, fuzzTime, parallel)
				mu.Lock()
				results = append(results, r)
				fmt.Fprintln(out, line(r))
				mu.Unlock()
			}
		}()
	}
	for _, t := range ts {
		queue <- t
	}
	close(queue)
	wg.Wait()
	return results
}

// waitForLoad blocks while the load average is above max. A load that cannot be
// read is reported and the target starts anyway: the check was verified at the
// start of the run, so a later failure is transient and saying so is enough.
func waitForLoad(errw io.Writer, mu *sync.Mutex, t target, max float64) {
	said := false
	for {
		l, err := loadAvg()
		if err != nil {
			mu.Lock()
			fmt.Fprintf(errw, "load average unreadable (%v): starting %s %s without the load check\n", err, t.pkg, t.name)
			mu.Unlock()
			return
		}
		if l <= max {
			return
		}
		if !said {
			mu.Lock()
			fmt.Fprintf(errw, "load %.2f above %.2f: %s %s waits\n", l, max, t.pkg, t.name)
			mu.Unlock()
			said = true
		}
		time.Sleep(loadPoll)
	}
}

func runOne(dir, logs string, t target, fuzzTime string, parallel int) result {
	r := result{t: t, v: vFail}
	r.log = filepath.Join(logs, strings.ReplaceAll(strings.TrimPrefix(t.pkg, "./"), "/", "_")+"-"+t.name+".log")
	if strings.HasPrefix(filepath.Base(r.log), ".") || strings.HasPrefix(filepath.Base(r.log), "-") {
		// "./." for the root package gives "." and a log named ".-Name.log".
		r.log = filepath.Join(logs, "root-"+t.name+".log")
	}
	lf, err := os.Create(r.log)
	if err != nil {
		r.note = err.Error()
		return r
	}
	defer lf.Close()
	cmd := exec.Command("go", "test", "-run=^$", "-fuzz=^"+t.name+"$", "-fuzztime="+fuzzTime,
		fmt.Sprintf("-parallel=%d", parallel), t.pkg)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = lf, lf
	start := time.Now()
	runErr := cmd.Run()
	r.dur = time.Since(start)
	if runErr == nil {
		r.v = vPass
		return r
	}
	b, err := os.ReadFile(r.log)
	if err != nil {
		r.note = "log unreadable: " + err.Error()
		return r
	}
	if p, ok := parseCrasher(string(b), t.pkg); ok {
		r.v, r.corpus = vCrash, p
	} else {
		r.note = runErr.Error()
	}
	return r
}

func line(r result) string {
	s := fmt.Sprintf("%s %s %s %s", r.v, r.t.pkg, r.t.name, r.dur.Round(100*time.Millisecond))
	if r.corpus != "" {
		s += " " + r.corpus
	} else if r.v == vFail {
		s += " (" + r.note + "; log " + r.log + ")"
	}
	return s
}

func summarize(out io.Writer, results []result) error {
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i].t, results[j].t
		if a.pkg != b.pkg {
			return a.pkg < b.pkg
		}
		return a.name < b.name
	})
	fmt.Fprintln(out, "== summary ==")
	var pass, fail, crash int
	for _, r := range results {
		fmt.Fprintln(out, line(r))
		switch r.v {
		case vPass:
			pass++
		case vFail:
			fail++
		case vCrash:
			crash++
		}
	}
	fmt.Fprintf(out, "%d targets: %d PASS, %d FAIL, %d CRASH\n", len(results), pass, fail, crash)
	if fail+crash > 0 {
		return &exitError{code: 1}
	}
	return nil
}

func waitCmd() *cobra.Command {
	var timeout, interval time.Duration
	cmd := &cobra.Command{
		Use:   "wait FILE SUBSTRING",
		Short: "Block until FILE contains SUBSTRING (exit 0), or --timeout passes (exit 1)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if interval <= 0 {
				return &exitError{2, errors.New("--interval must be positive")}
			}
			file, sub := args[0], args[1]
			deadline := time.Now().Add(timeout)
			for {
				b, err := os.ReadFile(file)
				if err == nil && strings.Contains(string(b), sub) {
					fmt.Fprintln(cmd.OutOrStdout(), "found")
					return nil
				}
				// A file that does not exist yet is the normal case of waiting for
				// a log to appear; any other read error is real.
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					return &exitError{2, err}
				}
				if !time.Now().Before(deadline) {
					fmt.Fprintln(cmd.OutOrStdout(), "timeout")
					return &exitError{code: 1}
				}
				time.Sleep(min(interval, time.Until(deadline)))
			}
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Minute, "give up after this long")
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "poll period")
	return cmd
}
