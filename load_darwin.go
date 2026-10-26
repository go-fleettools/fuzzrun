//go:build darwin

package main

import "golang.org/x/sys/unix"

func readLoadAvg() (float64, error) {
	b, err := unix.SysctlRaw("vm.loadavg")
	if err != nil {
		return 0, err
	}
	return parseSysctlLoadavg(b)
}
