package planted

import "testing"

// FuzzGood never fails.
func FuzzGood(f *testing.F) {
	f.Add([]byte("a"))
	f.Fuzz(func(t *testing.T, b []byte) { _ = len(b) })
}

// FuzzBad is the PLANTED failure: it fails on any input of two bytes or more.
// The seed is one byte so that the seed corpus passes (a failing seed writes no
// corpus file) and the first mutation that grows the input crashes it.
func FuzzBad(f *testing.F) {
	f.Add([]byte("a"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) >= 2 {
			t.Fatalf("planted failure on %q", b)
		}
	})
}
