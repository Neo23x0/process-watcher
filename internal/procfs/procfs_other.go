//go:build !linux

package procfs

import "github.com/Neo23x0/process-watcher/internal/collector"

// BootID has no meaning off Linux; a fixed value keeps the model testable.
func BootID() (string, error) { return "00000000-0000-4000-8000-000000000000", nil }

// ReadArgs is unavailable off Linux.
func ReadArgs(_ collector.Key, lim collector.ArgLimits) collector.Args {
	return collector.Args{State: collector.ArgsFailed, Limits: lim.Normalized()}
}
