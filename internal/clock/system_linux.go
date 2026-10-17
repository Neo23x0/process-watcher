package clock

import (
	"time"

	"golang.org/x/sys/unix"
)

// System is the real clock pair.
type System struct{}

// BootNS reads CLOCK_BOOTTIME, the same time base as bpf_ktime_get_boot_ns().
func (System) BootNS() uint64 { return BootNS() }

// Now returns the wall clock.
func (System) Now() time.Time { return time.Now() }

// BootNS reads CLOCK_BOOTTIME in nanoseconds.
func BootNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
