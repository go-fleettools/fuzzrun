package sub

import "testing"

// The same name as the root package's target, and the matrix does NOT pair it
// with ./sub: this one must stay a gap.
func FuzzShared(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {})
}

func FuzzSubOnly(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {})
}
