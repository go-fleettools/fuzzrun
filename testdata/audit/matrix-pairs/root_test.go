package pairs

import "testing"

// FuzzShared exists in BOTH packages of this module, and the matrix pairs it
// with this one only. It is what tells a paired expansion from a crossed one.
func FuzzShared(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {})
}

func FuzzRootOnly(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {})
}
