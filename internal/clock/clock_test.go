package clock

import (
	"testing"
	"time"
)

func TestToWallUsesTheCurrentMapping(t *testing.T) {
	f := &Fake{Boot: 9_000_124_000_000, Wall: time.Date(2026, 10, 17, 12, 0, 0, 124_000_000, time.UTC)}
	// 543 µs before "now" in boot time is 543 µs before "now" on the wall clock.
	got := ToWall(f, 9_000_123_456_789)
	if want := time.Date(2026, 10, 17, 12, 0, 0, 123_456_789, time.UTC); !got.Equal(want) {
		t.Errorf("got %s want %s", got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
	// A wall clock step does not leave a stale offset: the next conversion follows it.
	f.Wall = f.Wall.Add(time.Hour)
	if got := ToWall(f, 9_000_123_456_789); !got.Equal(time.Date(2026, 10, 17, 13, 0, 0, 123_456_789, time.UTC)) {
		t.Errorf("after a clock step: %s", got)
	}
	// A kernel time slightly in the future (the clocks are sampled independently) is not an error.
	if got := ToWall(f, f.Boot+1000); got.Sub(f.Wall) != 1000*time.Nanosecond {
		t.Errorf("future event: %v", got.Sub(f.Wall))
	}
	f.Advance(time.Second)
	if f.Boot != 9_001_124_000_000 {
		t.Error("Advance")
	}
}
