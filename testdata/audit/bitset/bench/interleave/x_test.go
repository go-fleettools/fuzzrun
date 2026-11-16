package main

import "testing"

// A target of a nested module: not part of the root module, so not audited.
func FuzzNested(f *testing.F) {}
