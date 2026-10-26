//go:build linux

package main

import "os"

func readLoadAvg() (float64, error) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}
	return parseProcLoadavg(b)
}
