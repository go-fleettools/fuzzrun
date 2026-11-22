package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// modulePath reads the `module` line of dir/go.mod.
func modulePath(dir string) (string, error) {
	f, err := os.Open(filepath.Join(dir, "go.mod"))
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`), nil
		}
	}
	return "", errors.New("no module line in " + filepath.Join(dir, "go.mod"))
}

// defaultCache is $GOCACHE/fuzz/<module path>: where `go test -fuzz` keeps the
// interesting inputs it found (only crashers are written under testdata/fuzz).
func defaultCache(dir string) (string, error) {
	mod, err := modulePath(dir)
	if err != nil {
		return "", err
	}
	c := exec.Command("go", "env", "GOCACHE")
	c.Dir = dir
	b, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("go env GOCACHE: %w", err)
	}
	return filepath.Join(strings.TrimSpace(string(b)), "fuzz", filepath.FromSlash(mod)), nil
}

type seedFile struct {
	path string
	size int64
}

// seedCorpus copies, per target directory of cache, the max smallest files not
// larger than maxBytes into dir/testdata/fuzz/<Target>/. It returns the number
// of files kept per target.
func seedCorpus(cache, dir string, max int, maxBytes int64) (map[string]int, error) {
	targets, err := os.ReadDir(cache)
	if err != nil {
		return nil, err
	}
	kept := map[string]int{}
	for _, t := range targets {
		if !t.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(cache, t.Name()))
		if err != nil {
			return nil, err
		}
		var es []seedFile
		for _, f := range files {
			p := filepath.Join(cache, t.Name(), f.Name())
			fi, err := os.Stat(p)
			if err != nil || fi.IsDir() || fi.Size() > maxBytes {
				continue
			}
			es = append(es, seedFile{p, fi.Size()})
		}
		sort.Slice(es, func(i, j int) bool {
			if es[i].size != es[j].size {
				return es[i].size < es[j].size
			}
			return es[i].path < es[j].path
		})
		if len(es) > max {
			es = es[:max]
		}
		out := filepath.Join(dir, "testdata", "fuzz", t.Name())
		if err := os.MkdirAll(out, 0o755); err != nil {
			return nil, err
		}
		for _, e := range es {
			b, err := os.ReadFile(e.path)
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(out, filepath.Base(e.path)), b, 0o644); err != nil {
				return nil, err
			}
		}
		kept[t.Name()] = len(es)
	}
	return kept, nil
}

func seedCorpusCmd() *cobra.Command {
	var cache, dir string
	var max int
	var maxBytes int64
	cmd := &cobra.Command{
		Use:   "seedcorpus",
		Short: "Commit the inputs a local `go test -fuzz` run cached as the seed corpus",
		Long: "Copies the inputs the Go fuzz engine cached for the module at --dir\n" +
			"(default $GOCACHE/fuzz/<module path>) into testdata/fuzz/<Target>/: per target\n" +
			"the --max smallest files, none over --max-bytes. Run `fuzzrun run --time 20s`\n" +
			"first; the corpus stays small and holds inputs only.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cache == "" {
				c, err := defaultCache(dir)
				if err != nil {
					return err
				}
				cache = c
			}
			kept, err := seedCorpus(cache, dir, max, maxBytes)
			if err != nil {
				return err
			}
			names := make([]string, 0, len(kept))
			total := 0
			for n, k := range kept {
				names = append(names, n)
				total += k
			}
			sort.Strings(names)
			for _, n := range names {
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %d files\n", n, kept[n])
			}
			fmt.Fprintf(cmd.OutOrStdout(), "total %d\n", total)
			return nil
		},
	}
	cmd.Flags().StringVar(&cache, "cache", "", "fuzz cache directory of the module (default $GOCACHE/fuzz/<module path>)")
	cmd.Flags().StringVar(&dir, "dir", ".", "module root")
	cmd.Flags().IntVar(&max, "max", 40, "files kept per target")
	cmd.Flags().Int64Var(&maxBytes, "max-bytes", 65536, "largest file kept")
	return cmd
}

// scanRepo reads .github/workflows/fuzz.yml of org/repo on the default branch
// and describes it: whether it exists, runs fuzzrun, and tolerates exit 1 (the
// `-ge 2` test fuzzrun workflow wrote before v0.8.0).
func scanRepo(client *http.Client, base, org, repo string) string {
	resp, err := client.Get(base + "/" + org + "/" + repo + "/HEAD/.github/workflows/fuzz.yml")
	if err != nil {
		return fmt.Sprintf("%s/%s NOT READ %v", org, repo, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("%s/%s NOT READ %v", org, repo, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return fmt.Sprintf("%s/%s no fuzz.yml", org, repo)
	default:
		return fmt.Sprintf("%s/%s NOT READ HTTP %d", org, repo, resp.StatusCode)
	}
	s := string(b)
	return fmt.Sprintf("%s/%s fuzzrun=%v tolerant=%v continue-on-error=%v", org, repo,
		strings.Contains(s, "fuzzrun"), strings.Contains(s, "-ge 2"), strings.Contains(s, "continue-on-error: true"))
}

func scanCmd() *cobra.Command {
	var org, base string
	cmd := &cobra.Command{
		Use:   "scan --org ORG REPO...",
		Short: "Say which repositories carry the exit-1-tolerant fuzz workflow",
		Long: "Reads .github/workflows/fuzz.yml of each REPO of ORG from raw.githubusercontent.com\n" +
			"(no API budget) and prints one line each. A repository whose file could not be\n" +
			"read is NOT READ, never an absence. Exit 1 when any repo is tolerant or not\n" +
			"read, 0 when none is.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, repos []string) error {
			if org == "" {
				return errors.New("--org is required")
			}
			client := &http.Client{Timeout: 30 * time.Second}
			bad := false
			for _, r := range repos {
				line := scanRepo(client, base, org, r)
				fmt.Fprintln(cmd.OutOrStdout(), line)
				if strings.Contains(line, "tolerant=true") || strings.Contains(line, "NOT READ") {
					bad = true
				}
			}
			if bad {
				return &exitError{code: 1}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "organisation")
	cmd.Flags().StringVar(&base, "base", "https://raw.githubusercontent.com", "raw content base URL")
	return cmd
}
