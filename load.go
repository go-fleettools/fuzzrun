package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// loadAvg returns the 1-minute load average. It is a variable so that tests can
// substitute it; the per-platform readLoadAvg is in load_*.go.
var loadAvg = readLoadAvg

// parseProcLoadavg parses the content of /proc/loadavg ("0.52 0.58 0.59 ...").
func parseProcLoadavg(b []byte) (float64, error) {
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, errors.New("empty /proc/loadavg")
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0, fmt.Errorf("/proc/loadavg: %w", err)
	}
	return v, nil
}

// parseSysctlLoadavg parses the raw value of the darwin sysctl vm.loadavg,
// which is `struct loadavg { fixpt_t ldavg[3]; long fscale; }`: three uint32
// fixed-point values, 4 bytes of padding, then an int64 scale, in host order.
func parseSysctlLoadavg(b []byte) (float64, error) {
	if len(b) < 24 {
		return 0, fmt.Errorf("vm.loadavg: %d bytes, want 24", len(b))
	}
	scale := binary.NativeEndian.Uint64(b[16:24])
	if scale == 0 {
		return 0, errors.New("vm.loadavg: zero scale")
	}
	return float64(binary.NativeEndian.Uint32(b[0:4])) / float64(scale), nil
}
