//go:build !linux

package app

import (
	"io"
	"runtime"

	"github.com/Neo23x0/process-watcher/internal/config"
)

// Doctor on a platform without a collector: it can only say so.
func Doctor(_ *config.Resolved, version string, w io.Writer) int {
	return report(w, []Check{
		{"process-watcher", StatusOK, version + " (" + runtime.GOOS + "/" + runtime.GOARCH + ")"},
		{"platform", StatusFail, "process-watcher monitors processes with eBPF and only runs on Linux (amd64, arm64)"},
	})
}
