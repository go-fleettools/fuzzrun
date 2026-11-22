package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// ⛔ What "a workflow fuzzes a target" means, taken from the go tool and not from
// the look of the YAML (go1.27.4, cmd/go/internal/test/test.go and
// testing/fuzz.go):
//
//   - -fuzz is an UNANCHORED regexp matched against the fuzz targets of ONE
//     package; the part after the first "/" selects sub-targets and is ignored here.
//   - a pattern that matches MORE THAN ONE target of the package fuzzes none
//     ("testing: will not fuzz, -fuzz matches more than one fuzz test"). go-simd/
//     floats's old `-fuzz FuzzAxpy` matched FuzzAxpy and FuzzAxpyRowsNoFMA, so
//     the step listing FuzzAxpy fuzzed nothing, while its continue-on-error hid it.
//   - -fuzz with more than one package ("./..." over a module with several
//     packages) is refused outright: "cannot use -fuzz flag with multiple packages".
//
// A step running `fuzzrun run` covers every target (or those of its --package).

// gap is a target no workflow fuzzes, with the reason.
type gap struct {
	t      target
	reason string
}

type auditReport struct {
	targets []target
	gaps    []gap
	blanket []string // "file: job/step" fuzz steps under continue-on-error: true
	notes   []string
	// uncertain lists fuzz steps the audit cannot read (a -fuzz pattern computed
	// at run time, a make target, a script, a working-directory). When there are
	// any, the uncovered targets are unsure, not gaps: the step might fuzz them.
	uncertain []string
	unsure    []gap
}

type wfFile struct {
	Jobs map[string]wfJob `yaml:"jobs"`
}

type wfJob struct {
	COE      any      `yaml:"continue-on-error"`
	Steps    []wfStep `yaml:"steps"`
	Strategy struct {
		Matrix map[string]any `yaml:"matrix"`
	} `yaml:"strategy"`
}

type wfStep struct {
	Name string `yaml:"name"`
	Run  string `yaml:"run"`
	COE  any    `yaml:"continue-on-error"`
	WD   string `yaml:"working-directory"`
}

var (
	matrixRef = regexp.MustCompile(`\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}`)
	// indirect: a fuzz run started through make, a script or a loop variable,
	// which the audit cannot read.
	indirectFuzz = regexp.MustCompile(`\b(make|just|task|npm run)\s+\S*fuzz|\.sh\b[^\n]*fuzz|scripts?/\S*fuzz|\bcd\s+\S+`)
)

func scalarStr(v any) (string, bool) {
	switch x := v.(type) {
	case string, int, float64, bool:
		return fmt.Sprint(x), true
	}
	return "", false
}

// listValues reads the scalar values of one matrix key's own list.
func listValues(v any) []string {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range l {
		if s, ok := scalarStr(e); ok {
			out = append(out, s)
		}
	}
	return out
}

// A combination is one job of a matrix: what GitHub gives each
// ${{ matrix.KEY }} for that job.
type combination map[string]string

// matrixCombinations lists the jobs a static matrix produces, and says whether
// the pairing is exact.
//
// ⛔ THE PAIRING IS THE POINT, AND EXPANDING EACH REFERENCE ALONE LOSES IT.
// go-crdt/crdt's fuzz lane is twenty `include` entries, each pairing a package
// with a target -- {pkg: ".", target: FuzzParseOps} -- so a per-key expansion
// crosses every package with every target and invents jobs that never ran.
// Coverage here is keyed by (package, target), so an invented job can only mark
// something covered when the SAME target name exists in the other package --
// and a false "covered" is the one answer an audit must never produce.
//
// GitHub's rules as this reads them: the list keys give the cross product,
// `exclude` removes the combinations it matches, and each `include` entry is a
// job of its own, which is the shape every fuzz matrix in this fleet uses. A
// matrix holding BOTH lists and `include` is not modelled: the two are crossed
// so that nothing is left unresolved, and exact is false so the caller can say
// the pairing is not one this read.
func matrixCombinations(m map[string]any) (out []combination, exact bool) {
	if len(m) == 0 {
		return nil, true
	}
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if k == "include" || k == "exclude" {
			continue
		}
		if len(listValues(v)) > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	product := []combination{{}}
	for _, k := range keys {
		var next []combination
		for _, c := range product {
			for _, v := range listValues(m[k]) {
				n := make(combination, len(c)+1)
				for ck, cv := range c {
					n[ck] = cv
				}
				n[k] = v
				next = append(next, n)
			}
		}
		product = next
	}
	if len(keys) == 0 {
		product = nil
	}
	product = withoutExcluded(product, m["exclude"])

	var inc []combination
	if l, ok := m["include"].([]any); ok {
		for _, e := range l {
			em, ok := e.(map[string]any)
			if !ok {
				continue
			}
			c := combination{}
			for k, v := range em {
				if s, ok := scalarStr(v); ok {
					c[k] = s
				}
			}
			if len(c) > 0 {
				inc = append(inc, c)
			}
		}
	}
	switch {
	case len(product) == 0:
		return inc, true
	case len(inc) == 0:
		return product, true
	default:
		out = append(out, product...)
		for _, i := range inc {
			for _, p := range product {
				n := make(combination, len(p)+len(i))
				for k, v := range p {
					n[k] = v
				}
				for k, v := range i {
					n[k] = v
				}
				out = append(out, n)
			}
		}
		return out, false
	}
}

// withoutExcluded drops the combinations an `exclude` entry matches: every key
// the entry names has that value. Ignoring exclude would mark a target covered
// by a job GitHub never runs.
func withoutExcluded(in []combination, exclude any) []combination {
	l, ok := exclude.([]any)
	if !ok || len(in) == 0 {
		return in
	}
	var out []combination
	for _, c := range in {
		excluded := false
		for _, e := range l {
			em, ok := e.(map[string]any)
			if !ok || len(em) == 0 {
				continue
			}
			all := true
			for k, v := range em {
				s, ok := scalarStr(v)
				if !ok || c[k] != s {
					all = false
					break
				}
			}
			if all {
				excluded = true
				break
			}
		}
		if !excluded {
			out = append(out, c)
		}
	}
	return out
}

// substitute replaces every ${{ matrix.KEY }} in s with this combination's
// value; ok is false when a reference has none, which leaves the text as it was
// so the caller still reports it as computed at run time.
func substitute(s string, c combination) (string, bool) {
	out, ok := s, true
	for _, ref := range matrixRef.FindAllStringSubmatch(s, -1) {
		v, found := c[ref[1]]
		if !found {
			ok = false
			continue
		}
		out = strings.ReplaceAll(out, ref[0], v)
	}
	return out, ok
}

// isTrue reports a continue-on-error value that is the literal true.
func isTrue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.TrimSpace(x) == "true"
	}
	return false
}

var (
	goTestInvoke = regexp.MustCompile(`\bgo\s+test\b`)
	shellVar     = regexp.MustCompile(`\$\{|\$\(|\$[A-Za-z_]`)
	cmdSep       = regexp.MustCompile(`&&|\|\||[;|]`)
)

// goTestValueFlags are the go test flags that take a value as the next word.
var goTestValueFlags = map[string]bool{
	"fuzz": true, "fuzztime": true, "fuzzminimizetime": true, "run": true, "parallel": true,
	"timeout": true, "count": true, "cpu": true, "tags": true, "bench": true, "benchtime": true,
	"p": true, "coverpkg": true, "covermode": true, "coverprofile": true, "mod": true,
	"ldflags": true, "gcflags": true, "exec": true, "vet": true, "o": true, "outputdir": true,
	"shuffle": true, "skip": true, "asmflags": true, "buildvcs": true, "overlay": true,
	"pkgdir": true, "trimpath": false, "C": true, "modfile": true, "toolexec": true,
	"cpuprofile": true, "memprofile": true, "blockprofile": true, "mutexprofile": true,
	"trace": true, "json": false,
}

// words splits a shell line into words, honouring single and double quotes.
func words(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	has := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, has = r, true
		case r == ' ' || r == '\t':
			if has || cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
		}
	}
	if has || cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// fuzzrunArgs reports whether seg invokes `fuzzrun run`, and returns the words
// after `run`. The program is any word whose last path element is fuzzrun,
// optionally with an @version — `fuzzrun`, `"$(go env GOPATH)/bin/fuzzrun"`,
// `github.com/go-fleettools/fuzzrun@v0.7.0` — read through words(), so a quoted
// path counts like a bare one (fuzzrun#18). Flags may sit between program and
// verb; a word starting with # ends the command.
func fuzzrunArgs(seg string) ([]string, bool) {
	ws := words(seg)
	for i, w := range ws {
		if strings.HasPrefix(w, "#") {
			return nil, false
		}
		base := w[strings.LastIndexByte(w, '/')+1:]
		if at := strings.IndexByte(base, '@'); at >= 0 {
			base = base[:at]
		}
		if base != "fuzzrun" {
			continue
		}
		j := i + 1
		for j < len(ws) && strings.HasPrefix(ws[j], "-") {
			j++
		}
		if j < len(ws) && ws[j] == "run" {
			return ws[j+1:], true
		}
	}
	return nil, false
}

// invocation is one `go test -fuzz PATTERN pkgs...` found in a run script.
type invocation struct {
	pattern string
	pkgs    []string
}

// scanRun reads one run: script and returns the `go test -fuzz` invocations and
// whether it invokes `fuzzrun run` (with its --package filters, if any).
func scanRun(script string) (invs []invocation, fuzzr bool, fuzzrPkgs []string) {
	script = strings.ReplaceAll(script, "\\\n", " ")
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		for _, seg := range cmdSep.Split(line, -1) {
			if ws, ok := fuzzrunArgs(seg); ok {
				fuzzr = true
				for i := 0; i < len(ws); i++ {
					switch {
					case ws[i] == "--package" && i+1 < len(ws):
						fuzzrPkgs = append(fuzzrPkgs, ws[i+1])
						i++
					case strings.HasPrefix(ws[i], "--package="):
						fuzzrPkgs = append(fuzzrPkgs, strings.TrimPrefix(ws[i], "--package="))
					}
				}
				continue
			}
			m := goTestInvoke.FindStringIndex(seg)
			if m == nil {
				continue
			}
			ws := words(seg[m[1]:])
			var inv invocation
			found := false
		args:
			for i := 0; i < len(ws); i++ {
				w := ws[i]
				if w == "-args" || w == "--args" {
					break args
				}
				if !strings.HasPrefix(w, "-") || w == "-" {
					inv.pkgs = append(inv.pkgs, w)
					continue
				}
				name, val, hasVal := strings.Cut(strings.TrimLeft(w, "-"), "=")
				if goTestValueFlags[name] && !hasVal && i+1 < len(ws) {
					val, hasVal = ws[i+1], true
					i++
				}
				if name == "fuzz" && hasVal {
					inv.pattern, found = val, true
				}
			}
			if found {
				invs = append(invs, inv)
			}
		}
	}
	return invs, fuzzr, fuzzrPkgs
}

// modulePackages lists the package directories of the module ("./a/b"): those
// holding a .go file, outside testdata, vendor, and dot or underscore dirs.
func modulePackages(dir string) ([]string, error) {
	seen := map[string]bool{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			n := d.Name()
			if p != dir && (n == "testdata" || n == "vendor" || strings.HasPrefix(n, ".") || strings.HasPrefix(n, "_")) {
				return filepath.SkipDir
			}
			if nestedModule(dir, p) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") {
			rel, err := filepath.Rel(dir, filepath.Dir(p))
			if err != nil {
				return err
			}
			seen["./"+filepath.ToSlash(rel)] = true
		}
		return nil
	})
	var pk []string
	for p := range seen {
		pk = append(pk, p)
	}
	sort.Strings(pk)
	return pk, err
}

// resolvePkgs expands go package arguments ("./...", "./a/...", "./a", ".") over
// the module's packages.
func resolvePkgs(args, all []string) []string {
	if len(args) == 0 {
		args = []string{"."}
	}
	var out []string
	seen := map[string]bool{}
	for _, a := range args {
		a = strings.TrimSuffix(a, "/")
		var hit []string
		if base, ok := strings.CutSuffix(a, "..."); ok {
			base = strings.TrimSuffix(base, "/")
			if base == "" || base == "." {
				base = "./."
			}
			for _, p := range all {
				if base == "./." || p == base || strings.HasPrefix(p, base+"/") {
					hit = append(hit, p)
				}
			}
		} else {
			if a == "." || a == "" {
				a = "./."
			} else if !strings.HasPrefix(a, "./") {
				a = "./" + a
			}
			for _, p := range all {
				if p == a {
					hit = append(hit, p)
				}
			}
		}
		for _, p := range hit {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// audit reads the module at dir and its workflows. An error means nothing could
// be read (exit 2).
func audit(dir string) (*auditReport, error) { return auditAt(dir, true) }

// hasNestedModule reports whether a go.mod exists below dir (testdata, vendor,
// dot and underscore directories skipped, as the go command skips them).
func hasNestedModule(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || found {
			return filepath.SkipDir
		}
		if d.IsDir() {
			n := d.Name()
			if p != dir && (n == "testdata" || n == "vendor" || strings.HasPrefix(n, ".") || strings.HasPrefix(n, "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "go.mod" {
			found = true
		}
		return nil
	})
	return found
}

// auditAt is audit; with requireRoot false a repository whose go.mod files are
// all nested is audited as one tree (packages are then relative to the repo).
func auditAt(dir string, requireRoot bool) (*auditReport, error) {
	if requireRoot && !isModule(dir) {
		return nil, fmt.Errorf("no go.mod in %s", dir)
	}
	ts, err := discover(dir, nil)
	if err != nil {
		return nil, err
	}
	rep := &auditReport{targets: ts}
	if len(ts) == 0 {
		rep.notes = append(rep.notes, "no fuzz targets: nothing to audit")
		return rep, nil
	}
	files, err := filepath.Glob(filepath.Join(dir, ".github", "workflows", "*.yml"))
	if err != nil {
		return nil, err
	}
	more, _ := filepath.Glob(filepath.Join(dir, ".github", "workflows", "*.yaml"))
	files = append(files, more...)
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no workflows in %s/.github/workflows", dir)
	}
	all, err := modulePackages(dir)
	if err != nil {
		return nil, err
	}

	covered := map[target]bool{}
	why := map[target]string{} // the reason a mentioned target is still a gap
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var wf wfFile
		if err := yaml.Unmarshal(b, &wf); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		base := filepath.ToSlash(filepath.Join(".github", "workflows", filepath.Base(f)))
		jobs := make([]string, 0, len(wf.Jobs))
		for j := range wf.Jobs {
			jobs = append(jobs, j)
		}
		sort.Strings(jobs)
		for _, jn := range jobs {
			job := wf.Jobs[jn]
			for i, st := range job.Steps {
				invs, fuzzr, fpk := scanRun(st.Run)
				label := st.Name
				if label == "" {
					label = fmt.Sprintf("step %d", i+1)
				}
				indirect := !fuzzr && strings.Contains(strings.ToLower(st.Run), "fuzz") &&
					(indirectFuzz.MatchString(st.Run) || (st.WD != "" && len(invs) > 0))
				if indirect {
					rep.uncertain = append(rep.uncertain, fmt.Sprintf("%s: job %s, %q: fuzz run through make, a script or another directory", base, jn, label))
				}
				if !fuzzr && len(invs) == 0 {
					continue
				}
				if isTrue(st.COE) || isTrue(job.COE) {
					rep.blanket = append(rep.blanket, fmt.Sprintf("%s: job %s, %q: continue-on-error: true", base, jn, label))
				}
				if fuzzr {
					for _, t := range ts {
						if len(fpk) == 0 || matchPkg(t.pkg, fpk) {
							covered[t] = true
						}
					}
				}
				// ⛔ THE PACKAGE IS SUBSTITUTED TOO, which is what this used to
				// miss: the -fuzz pattern was expanded and the package operand
				// beside it was left as `${{ matrix.pkg }}`, so the step was
				// classified as computed at run time and every target it covers
				// came out UNCERTAIN. Measured on go-crdt/crdt: 35 targets, 35
				// uncertain, exit 0 -- a lane green while deciding nothing,
				// over a matrix written out in full in the file.
				combos, exact := matrixCombinations(job.Strategy.Matrix)
				if len(combos) == 0 {
					combos = []combination{nil} // no matrix: one pass, as written
				}
				// ⛔ AND THE SUBSTITUTION IS ON THE SCRIPT, NOT ON THE PARSED
				// OPERANDS. Substituting each operand was the obvious shape and
				// it did nothing: `words` splits on whitespace, so
				// `${{ matrix.pkg }}` arrives as THREE words -- `${{`,
				// `matrix.pkg`, `}}` -- and no one of them holds a reference to
				// replace. The test written for the defect reproduced it
				// unchanged, which is how this was found rather than shipped.
				// Substituting before the scan resolves the pattern, the
				// package and anything else the step reads, by one rule.
				seen := map[string]bool{}
				for _, c := range combos {
					script := st.Run
					if c != nil {
						script, _ = substitute(script, c)
					}
					cinvs, _, _ := scanRun(script)
					for _, inv := range cinvs {
						// A reference no combination resolves keeps its `${{`,
						// and auditInvocation still calls it computed: that is
						// the honest answer and it is left alone here.
						key := inv.pattern + "\x00" + strings.Join(inv.pkgs, " ")
						if seen[key] {
							continue // the same job twice says nothing twice
						}
						seen[key] = true
						auditInvocation(rep, ts, all, inv, base, jn, label, covered, why)
					}
				}
				if !exact && len(invs) > 0 {
					rep.notes = append(rep.notes, fmt.Sprintf("%s: job %s, %q: the matrix holds both a list and `include`, so the combinations were crossed rather than paired: a target may read as covered by a job that never ran", base, jn, label))
				}
			}
		}
	}
	for _, t := range ts {
		if !covered[t] {
			r := why[t]
			if r == "" {
				r = "no workflow fuzzes it"
			}
			if len(rep.uncertain) > 0 {
				rep.unsure = append(rep.unsure, gap{t, r})
			} else {
				rep.gaps = append(rep.gaps, gap{t, r})
			}
		}
	}
	return rep, nil
}

func auditInvocation(rep *auditReport, ts []target, all []string, inv invocation, file, job, label string, covered map[target]bool, why map[target]string) {
	where := fmt.Sprintf("%s: job %s, %q", file, job, label)
	computed := shellVar.MatchString(inv.pattern) || strings.Contains(inv.pattern, "${{")
	for _, p := range inv.pkgs {
		computed = computed || strings.Contains(p, "$")
	}
	if computed {
		rep.uncertain = append(rep.uncertain, fmt.Sprintf("%s: -fuzz %q over %v is computed at run time", where, inv.pattern, inv.pkgs))
		return
	}
	pat, _, _ := strings.Cut(inv.pattern, "/")
	re, err := regexp.Compile(pat)
	if err != nil {
		rep.notes = append(rep.notes, fmt.Sprintf("%s: -fuzz %q is not a regexp (%v): counted as covering nothing", where, inv.pattern, err))
		return
	}
	pkgs := resolvePkgs(inv.pkgs, all)
	if len(pkgs) != 1 {
		msg := fmt.Sprintf("refused by go test (cannot use -fuzz flag with multiple packages): %s: -fuzz %q over %d packages", where, inv.pattern, len(pkgs))
		if len(pkgs) == 0 {
			msg = fmt.Sprintf("refused by go test (no packages to test): %s: -fuzz %q", where, inv.pattern)
		}
		rep.notes = append(rep.notes, msg)
		for _, t := range ts {
			if re.MatchString(t.name) && why[t] == "" {
				why[t] = "named in a step go test refuses (" + msg + ")"
			}
		}
		return
	}
	var hit []target
	for _, t := range ts {
		if t.pkg == pkgs[0] && re.MatchString(t.name) {
			hit = append(hit, t)
		}
	}
	switch {
	case len(hit) == 1:
		covered[hit[0]] = true
	case len(hit) > 1:
		var names []string
		for _, t := range hit {
			names = append(names, t.name)
		}
		msg := fmt.Sprintf("-fuzz %q matches %d targets of %s (%s): go test will not fuzz", inv.pattern, len(hit), pkgs[0], strings.Join(names, ", "))
		rep.notes = append(rep.notes, where+": "+msg)
		for _, t := range hit {
			if why[t] == "" {
				why[t] = "named but ambiguous: " + msg
			}
		}
	}
}

func (r *auditReport) write(out io.Writer) {
	for _, n := range r.notes {
		fmt.Fprintln(out, "NOTE", n)
	}
	for _, g := range r.gaps {
		fmt.Fprintf(out, "GAP %s %s: %s\n", g.t.pkg, g.t.name, g.reason)
	}
	for _, b := range r.blanket {
		fmt.Fprintln(out, "BLANKET", b)
	}
	for _, u := range r.uncertain {
		fmt.Fprintln(out, "UNCERTAIN step", u)
	}
	for _, g := range r.unsure {
		fmt.Fprintf(out, "UNCERTAIN %s %s: %s, and a step the audit cannot read may fuzz it\n", g.t.pkg, g.t.name, g.reason)
	}
	fmt.Fprintf(out, "audit: %d targets, %d without a workflow, %d blanket continue-on-error, %d uncertain\n",
		len(r.targets), len(r.gaps), len(r.blanket), len(r.unsure))
}

func auditCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Report the fuzz targets no workflow fuzzes, and fuzz steps under a blanket continue-on-error",
		Long: `Parses the test files of the module at --dir for FuzzXxx targets, reads
.github/workflows/*.yml and reports each target no workflow fuzzes. A step that
runs "fuzzrun run" covers every target; otherwise only a "go test -fuzz"
that go test would really run counts (the pattern is an unanchored regexp, must
match exactly one target, and the step must name a single package).

Exit status: 0 everything covered (or no targets), 1 gaps or a blanket
continue-on-error, 2 nothing could be read (no go.mod, no workflows, a parse error,
or every target uncertain because no step fuzzing it could be read).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep, err := audit(dir)
			if err != nil {
				return &exitError{2, err}
			}
			rep.write(cmd.OutOrStdout())
			if len(rep.gaps)+len(rep.blanket) > 0 {
				return &exitError{code: 1}
			}
			// ⛔ EVERY TARGET UNCERTAIN IS AN AUDIT THAT DECIDED NOTHING, and it
			// used to exit 0. go-crdt/crdt measured it before #15: 35 targets,
			// 35 uncertain, a green lane over a workflow the audit could not
			// read. An answer not obtained is not a negative, so it is the
			// "could not be read" status. A PARTLY uncertain module still
			// exits 0: some target was read as covered, and the UNCERTAIN lines
			// name the rest.
			if len(rep.targets) > 0 && len(rep.unsure) == len(rep.targets) {
				return &exitError{2, fmt.Errorf("all %d targets are uncertain: no workflow step could be read as fuzzing any of them", len(rep.targets))}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", ".", "module root")
	return cmd
}

var errNoRepos = errors.New("no repositories found")

// censusCmd runs the audit over every repository directory found two levels
// below --root (<org>/<repo>, the layout of gorequires --clone-dir) and writes a
// report.
func censusCmd() *cobra.Command {
	var root, report string
	cmd := &cobra.Command{
		Use:   "census",
		Short: "Audit every clone under --root/<org>/<repo> and write a report",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dirs, err := filepath.Glob(filepath.Join(root, "*", "*"))
			if err != nil {
				return &exitError{2, err}
			}
			if len(dirs) == 0 {
				return &exitError{2, errNoRepos}
			}
			var sb strings.Builder
			var read, withTargets, withGaps, withBlanket, noWorkflow, unread, uncertain, nested int
			for _, d := range dirs {
				if st, err := os.Stat(d); err != nil || !st.IsDir() {
					continue
				}
				name, _ := filepath.Rel(root, d)
				rep, err := audit(d)
				if err != nil && !isModule(d) && hasNestedModule(d) {
					rep, err = auditAt(d, false)
					if err == nil {
						nested++
					}
				}
				if err != nil {
					unread++
					if strings.HasPrefix(err.Error(), "no workflows") {
						noWorkflow++
						fmt.Fprintf(&sb, "NOWORKFLOW %s\n", name)
					} else if !strings.HasPrefix(err.Error(), "no go.mod") {
						fmt.Fprintf(&sb, "UNREAD %s: %v\n", name, err)
					}
					continue
				}
				read++
				if len(rep.targets) == 0 {
					continue
				}
				withTargets++
				if len(rep.unsure) > 0 {
					uncertain++
					fmt.Fprintf(&sb, "UNCERTAIN %s %d/%d\n", name, len(rep.unsure), len(rep.targets))
				}
				if len(rep.gaps) > 0 {
					withGaps++
					fmt.Fprintf(&sb, "GAPS %s %d/%d\n", name, len(rep.gaps), len(rep.targets))
					for _, g := range rep.gaps {
						fmt.Fprintf(&sb, "  GAP %s %s: %s\n", g.t.pkg, g.t.name, g.reason)
					}
				}
				if len(rep.blanket) > 0 {
					withBlanket++
					fmt.Fprintf(&sb, "BLANKET %s %d\n", name, len(rep.blanket))
					for _, b := range rep.blanket {
						fmt.Fprintf(&sb, "  %s\n", b)
					}
				}
			}
			sum := fmt.Sprintf("census: %d directories; %d audited, %d unaudited (%d of them have fuzz targets but no workflow); %d audited have fuzz targets, %d with gaps, %d uncertain, %d with a blanket continue-on-error step (%d audited have only nested modules)\n",
				len(dirs), read, unread, noWorkflow, withTargets, withGaps, uncertain, withBlanket, nested)
			fmt.Fprint(cmd.OutOrStdout(), sum)
			if report != "" {
				if err := os.WriteFile(report, []byte(sum+sb.String()), 0o644); err != nil {
					return &exitError{2, err}
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&root, "root", ".", "directory holding <org>/<repo> clones")
	cmd.Flags().StringVar(&report, "report", "", "write the report to this file")
	return cmd
}
