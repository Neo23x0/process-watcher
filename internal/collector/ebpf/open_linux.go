//go:build linux

package ebpf

import "github.com/Neo23x0/process-watcher/internal/collector"

// Open starts the eBPF collector. It is the platform independent entry point
// used by the agent.
func Open(opts collector.Options) (collector.Collector, error) {
	c, err := New(opts)
	if err != nil {
		return nil, err
	}
	return c, nil
}
