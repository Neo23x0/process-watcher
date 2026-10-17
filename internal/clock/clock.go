// Package clock relates the kernel's CLOCK_BOOTTIME timestamps to UTC.
//
// Kernel records carry CLOCK_BOOTTIME nanoseconds (monotonic, includes time
// spent suspended). The wall clock can jump, so it is never used for ordering.
// A timestamp is converted by sampling both clocks back to back at conversion
// time:
//
//	utc(event) = wall_now - (boottime_now - boottime(event))
//
// This reflects the wall clock as it is at processing time; no offset is
// cached, so an NTP step or a manual change does not leave a stale offset.
package clock

import "time"

// Clock provides the two clocks that are related by ToWall.
type Clock interface {
	// BootNS is the current CLOCK_BOOTTIME in nanoseconds.
	BootNS() uint64
	// Now is the current wall clock time.
	Now() time.Time
}

// ToWall converts a CLOCK_BOOTTIME timestamp into UTC.
func ToWall(c Clock, bootNS uint64) time.Time {
	boot := c.BootNS()
	wall := c.Now().UTC()
	if bootNS <= boot {
		return wall.Add(-time.Duration(boot - bootNS))
	}
	return wall.Add(time.Duration(bootNS - boot))
}

// Fake is a manually driven clock for tests.
type Fake struct {
	Boot uint64
	Wall time.Time
}

func (f *Fake) BootNS() uint64 { return f.Boot }
func (f *Fake) Now() time.Time { return f.Wall }

// Advance moves both clocks forward.
func (f *Fake) Advance(d time.Duration) {
	f.Boot += uint64(d)
	f.Wall = f.Wall.Add(d)
}
