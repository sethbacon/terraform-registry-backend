// Command coverfilter strips coverage entries for functions annotated with
//
//	// coverage:skip:integration-only
//
// from a Go coverage profile.  Such functions require a live external
// dependency (DB, SCM, OIDC issuer, scanner binary) to exercise and cannot be
// meaningfully unit-tested; keeping them in the denominator of the unit-test
// coverage metric understates the quality of the tested surface.
//
// Usage:
//
//	go run ./scripts/coverfilter -in coverage.out -out coverage.filtered.out
package main

import (
	"bufio"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const skipMarker = "coverage:skip:"

// skipRange represents a half-open [startLine, endLine] byte-line range in a
// single file that should be stripped from the coverage profile.
type skipRange struct {
	startLine int
	endLine   int
}

func main() {
	inPath := flag.String("in", "coverage.out", "input coverage profile")
	outPath := flag.String("out", "coverage.filtered.out", "output coverage profile")
	root := flag.String("root", ".", "module root to scan for source files")
	flag.Parse()

	skips, err := collectSkipRanges(*root)
	if err != nil {
		log.Fatalf("collect skip ranges: %v", err)
	}

	in, err := os.Open(*inPath) // #nosec G304 -- path is a CLI flag
	if err != nil {
		log.Fatalf("open input: %v", err)
	}
	defer in.Close()

	out, err := os.Create(*outPath) // #nosec G304 -- path is a CLI flag
	if err != nil {
		log.Fatalf("create output: %v", err)
	}
	defer out.Close()

	w := bufio.NewWriter(out)
	defer w.Flush()

	scanner := bufio.NewScanner(in)
	// Allow large coverage profiles.
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)

	var stripped, kept int
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			// Header: "mode: atomic" (or set/count)
			_, _ = w.WriteString(line + "\n")
			first = false
			continue
		}
		if shouldStrip(line, skips) {
			stripped++
			continue
		}
		kept++
		_, _ = w.WriteString(line + "\n")
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("scan: %v", err)
	}
	fmt.Fprintf(os.Stderr, "coverfilter: kept %d blocks, stripped %d blocks\n", kept, stripped)
}

// collectSkipRanges walks the module rooted at root and returns a map of
// absolute file paths → skipRanges for every function whose preceding doc
// comment contains the integration-only marker.
func collectSkipRanges(root string) (map[string][]skipRange, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]skipRange)
	fset := token.NewFileSet()

	err = filepath.Walk(absRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip vendor and .git to speed things up.
			name := info.Name()
			if name == "vendor" || name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			// Non-fatal — just skip files we can't parse.
			return nil
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Doc == nil {
				continue
			}
			var hasMarker bool
			for _, c := range fd.Doc.List {
				if strings.Contains(c.Text, skipMarker) {
					hasMarker = true
					break
				}
			}
			if !hasMarker {
				continue
			}
			start := fset.Position(fd.Pos()).Line
			end := fset.Position(fd.End()).Line
			result[path] = append(result[path], skipRange{startLine: start, endLine: end})
		}
		return nil
	})
	return result, err
}

// shouldStrip returns true when the coverage block described by the given
// profile line falls entirely inside one of the skip ranges.  Profile lines
// have the format:
//
//	path/to/file.go:startLine.startCol,endLine.endCol numStmts count
func shouldStrip(line string, skips map[string][]skipRange) bool {
	// Split on the final colon before the byte range.
	colon := strings.LastIndex(line, ":")
	if colon < 0 {
		return false
	}
	filePart := line[:colon]
	rangePart := line[colon+1:]

	// Parse "startLine.startCol,endLine.endCol numStmts count"
	spaceIdx := strings.Index(rangePart, " ")
	if spaceIdx < 0 {
		return false
	}
	byteRange := rangePart[:spaceIdx]
	commaIdx := strings.Index(byteRange, ",")
	if commaIdx < 0 {
		return false
	}
	startLine, err := parseLine(byteRange[:commaIdx])
	if err != nil {
		return false
	}
	endLine, err := parseLine(byteRange[commaIdx+1:])
	if err != nil {
		return false
	}

	// Profile uses module path (github.com/org/repo/pkg/file.go). We match by
	// file suffix — any registered skip whose absolute path ends with the same
	// package-relative path counts.
	for absPath, ranges := range skips {
		if !pathSuffixMatches(absPath, filePart) {
			continue
		}
		for _, r := range ranges {
			if startLine >= r.startLine && endLine <= r.endLine {
				return true
			}
		}
	}
	return false
}

// parseLine extracts the line number from a "line.col" pair.
func parseLine(s string) (int, error) {
	dot := strings.Index(s, ".")
	if dot < 0 {
		return 0, fmt.Errorf("no dot in %q", s)
	}
	return strconv.Atoi(s[:dot])
}

// pathSuffixMatches returns true if the absolute source path refers to the
// same file as the module-path string from the coverage profile.  We don't
// know the module prefix here, so we iterate over progressively shorter
// suffixes of the module path (dropping one leading segment per iteration)
// and check whether the absolute path ends with that suffix.  This works for
// any layout in which the on-disk path and the module path share a trailing
// subset of components (e.g. both end in "internal/api/router.go").
//
// A suffix consisting of the bare filename alone is rejected to avoid
// false positives when two packages contain files with the same name
// (e.g. both "internal/api/router.go" and "internal/mirror/router.go").
func pathSuffixMatches(absPath, modPath string) bool {
	// Normalize backslashes to forward slashes regardless of host OS.
	// filepath.ToSlash is a no-op on Linux (separator is '/'), but we may
	// receive Windows-style absolute paths (e.g. when this binary processes
	// a coverage profile recorded on a Windows developer's machine), so we
	// replace backslashes explicitly.
	abs := strings.ReplaceAll(absPath, "\\", "/")
	parts := strings.Split(modPath, "/")
	// Require at least 2 trailing segments (package dir + file) so bare
	// filenames can't cause cross-package false matches.
	maxStart := len(parts) - 2
	if maxStart < 0 {
		maxStart = 0
	}
	for i := 0; i <= maxStart; i++ {
		suffix := strings.Join(parts[i:], "/")
		if strings.HasSuffix(abs, "/"+suffix) {
			return true
		}
	}
	return false
}
