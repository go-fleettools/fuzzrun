package bitset

// Signatures of go-simd/bitset's 7 fuzz targets; fuzz.yml beside is its own
// (every step runs ./... , which is ONE package because bench/interleave is a
// nested module).

import "testing"

func FuzzAnd(f *testing.F)    {}
func FuzzAndNot(f *testing.F) {}
func FuzzBools(f *testing.F)  {}
func FuzzCount(f *testing.F)  {}
func FuzzCounts(f *testing.F) {}
func FuzzOr(f *testing.F)     {}
func FuzzXor(f *testing.F)    {}
