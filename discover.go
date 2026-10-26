package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// target is one fuzz function: pkg is the package directory relative to the
// module root, in the form "./sub/dir" ("./." for the root).
type target struct{ pkg, name string }

// isFuzzFunc reports whether d is a top-level function the go tool treats as a
// fuzz target: named FuzzXxx (the rune after "Fuzz" not lower case) with exactly
// one parameter of type *testing.F.
func isFuzzFunc(d *ast.FuncDecl) bool {
	if d.Recv != nil || !strings.HasPrefix(d.Name.Name, "Fuzz") {
		return false
	}
	rest := d.Name.Name[len("Fuzz"):]
	if r, _ := utf8.DecodeRuneInString(rest); rest != "" && unicode.IsLower(r) {
		return false
	}
	ps := d.Type.Params
	if ps == nil || len(ps.List) != 1 || len(ps.List[0].Names) > 1 {
		return false
	}
	star, ok := ps.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "F" {
		return false
	}
	_, ok = sel.X.(*ast.Ident)
	return ok
}

// fuzzNames parses one test file and returns its fuzz target names.
func fuzzNames(file string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && isFuzzFunc(fd) {
			out = append(out, fd.Name.Name)
		}
	}
	return out, nil
}

// discover walks the module at dir for *_test.go files (skipping .git and
// testdata) and returns every fuzz target, sorted. A non-empty patterns list
// keeps only the targets whose package matches one of them.
func discover(dir string, patterns []string) ([]target, error) {
	var ts []target
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		names, err := fuzzNames(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, filepath.Dir(p))
		if err != nil {
			return err
		}
		for _, n := range names {
			ts = append(ts, target{"./" + filepath.ToSlash(rel), n})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].pkg != ts[j].pkg {
			return ts[i].pkg < ts[j].pkg
		}
		return ts[i].name < ts[j].name
	})
	if len(patterns) == 0 {
		return ts, nil
	}
	var kept []target
	for _, t := range ts {
		if matchPkg(t.pkg, patterns) {
			kept = append(kept, t)
		}
	}
	return kept, nil
}

// matchPkg matches a "./a/b" package against path.Match patterns, written with
// or without the leading "./". A trailing "/..." matches the subtree.
func matchPkg(pkg string, patterns []string) bool {
	pkg = strings.TrimPrefix(pkg, "./")
	for _, p := range patterns {
		p = strings.TrimPrefix(p, "./")
		if base, ok := strings.CutSuffix(p, "/..."); ok {
			if pkg == base || strings.HasPrefix(pkg, base+"/") {
				return true
			}
			continue
		}
		if ok, _ := path.Match(p, pkg); ok {
			return true
		}
	}
	return false
}

// isModule reports whether dir holds a go.mod.
func isModule(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, "go.mod"))
	return err == nil && !st.IsDir()
}
