//go:build !linux

package ebpf

import (
	"runtime"

	"github.com/Neo23x0/process-watcher/internal/collector"
)

// Open fails on platforms without eBPF: the monitor is Linux only.
func Open(collector.Options) (collector.Collector, error) {
	return nil, &collector.PrerequisiteError{
		Check:  "platform",
		Detail: "process-watcher monitors processes with eBPF and only runs on Linux (amd64, arm64); this is " + runtime.GOOS + "/" + runtime.GOARCH,
		Err:    collector.ErrUnsupported,
	}
}
