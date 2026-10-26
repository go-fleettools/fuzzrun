// Command fuzzrun runs every Go fuzz target of a module, several at once,
// within an optional load budget, and reports the crashers it finds.
//
// Exit status of "run": 0 every target passed, 1 at least one failure or
// crasher, 2 the run could not be made. Of "wait": 0 found, 1 timeout, 2 error.
package main

import (
	"errors"
	"fmt"
	"os"
)

// osExit is a variable so that a test can observe the status without ending
// the test binary.
var osExit = os.Exit

// exitError carries a process status through cobra's RunE.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.err.Error()
}

func main() {
	err := RootCmd().Execute()
	if err == nil {
		return
	}
	var ee *exitError
	if errors.As(err, &ee) {
		// Status 1 has already been described by the summary; only a failure to
		// run needs saying again.
		if ee.code != 1 && ee.err != nil {
			fmt.Fprintln(os.Stderr, "⛔", ee.err)
		}
		osExit(ee.code)
		return
	}
	fmt.Fprintln(os.Stderr, "⛔", err)
	osExit(2)
}
