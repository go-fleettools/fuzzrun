module github.com/go-fleettools/fuzzrun

// ⛔ THE PATCH, NOT `go 1.27`: this line is the only one of the three Go pins
// that a CONSUMER honours — `go install` with GOTOOLCHAIN=local obeys it, while
// the CI pin merely builds our artefacts and the toolchain stamped in a binary
// describes one executable. It is also the version govulncheck judges the
// standard library by, through `go-version-file: go.mod`.
//
// Raised to 1.27.4 on 2026-11-15 for GO-2026-6859 — net/http, fix RELEASED in
// 1.27.4. Found by `modfloor --floor 1.27.4` reading the directive this module
// PUBLISHED at v0.1.0, from the module proxy: eight of the eleven published
// modules of this organisation read BELOW at that moment, this one among them,
// and it had no comment here saying what the line was for.
//
// ⛔ RENOVATE WILL NEVER OFFER THIS UPDATE — measured on 2026-11-15, not
// assumed. Its github-actions manager maintains the CI pin (`with: go-version`,
// dependency `go`, type uses-with: go-fleettools/docs#29 is exactly that), and
// its gomod manager SEES this directive — the dependency dashboard lists it
// under "Detected Dependencies" — yet offers nothing for it. The gate for that
// belongs on a clock, as modfloor beside the nightly vulnscan sweep.
go 1.27.4

require (
	github.com/spf13/cobra v1.10.2
	golang.org/x/sys v0.49.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
)
