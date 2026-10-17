//go:build !linux

package ebpf

import "github.com/Neo23x0/process-watcher/internal/collector"

// Preflight fails off Linux.
func Preflight() error {
	_, err := Open(collector.Options{})
	return err
}
