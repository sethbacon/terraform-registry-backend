// Package ci holds tests over this repository's own CI configuration rather
// than over the server.
//
// It exists because one of the merge gates is not Go, or YAML a linter
// understands, but a bash script embedded in .github/workflows/pr-checks.yml.
// actionlint checks its syntax and zizmor checks the workflow around it;
// nothing else executes it. A package with no production code is the price of
// running that script somewhere `go test ./internal/...` will reach, which is
// the only place in this repository where a check is proved rather than
// assumed.
//
// Anything added here must read the committed configuration and assert against
// it. A copy of the thing under test would drift from it, which is the defect
// one level up.
package ci
