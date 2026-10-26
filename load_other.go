//go:build !darwin && !linux

package main

import "errors"

func readLoadAvg() (float64, error) {
	return 0, errors.New("the load average is not readable on this platform")
}
