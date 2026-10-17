//go:build !linux

package clock

import "time"

var start = time.Now()

// System is a development stand-in: the agent only runs on Linux, but the
// model code is built and tested elsewhere.
type System struct{}

func (System) BootNS() uint64 { return BootNS() }
func (System) Now() time.Time { return time.Now() }

// BootNS approximates CLOCK_BOOTTIME by the process uptime (non-Linux only).
func BootNS() uint64 { return uint64(time.Since(start)) }
