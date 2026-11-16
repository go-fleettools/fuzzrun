package floats

// The 18 fuzz targets of go-simd/floats at e02abc2 (signatures only; the
// bodies are the library's and irrelevant to the audit). Real names, real
// workflows: testdata/audit/floats-old/.github/workflows/fuzz.yml is that
// repository's nightly fuzz workflow before #66 (9 targets named by hand), and
// floats-new's is the one after (fuzzrun run).

import "testing"

func FuzzCDotC(f *testing.F)            {}
func FuzzConjReverse(f *testing.F)      {}
func FuzzExtrema32(f *testing.F)        {}
func FuzzMDCTFold(f *testing.F)         {}
func FuzzDot(f *testing.F)              {}
func FuzzDistance(f *testing.F)         {}
func FuzzElem(f *testing.F)             {}
func FuzzAxpy(f *testing.F)             {}
func FuzzGather(f *testing.F)           {}
func FuzzMaxAbsMul(f *testing.F)        {}
func FuzzPairwise(f *testing.F)         {}
func FuzzMulAddRows(f *testing.F)       {}
func FuzzNoFMAKernels(f *testing.F)     {}
func FuzzRound(f *testing.F)            {}
func FuzzAxpyRowsNoFMA(f *testing.F)    {}
func FuzzSquaredMagnitude(f *testing.F) {}
func FuzzSumPairwise(f *testing.F)      {}
func FuzzCMulTwiddle(f *testing.F)      {}
