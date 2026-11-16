package xz

// Signatures of the three fuzz targets of go-compressions/xz; fuzz.yml beside is that repository's own.

import "testing"

func FuzzXZ(f *testing.F)    {}
func FuzzLZMA(f *testing.F)  {}
func FuzzLZMA2(f *testing.F) {}
