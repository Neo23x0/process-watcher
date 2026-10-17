package app

import (
	"fmt"
	"io"
)

// Status of a doctor check.
type Status string

const (
	StatusOK   Status = "OK"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
)

// Check is one line of the doctor report.
type Check struct {
	Name   string
	Status Status
	Detail string
}

// report prints the checks and returns the exit code: 3 if any check failed.
func report(w io.Writer, checks []Check) int {
	code := ExitOK
	for _, c := range checks {
		fmt.Fprintf(w, "[%-4s] %-22s %s\n", c.Status, c.Name, c.Detail)
		if c.Status == StatusFail {
			code = ExitPlatform
		}
	}
	if code == ExitOK {
		fmt.Fprintln(w, "\nAll required checks passed: this host can run process-watcher.")
	} else {
		fmt.Fprintln(w, "\nAt least one required check failed: process-watcher will refuse to start (exit code 3).")
	}
	return code
}
