package replay

import (
	"testing"
	"time"

	"github.com/Neo23x0/process-watcher/internal/collector"
)

func TestNextReturnsPushedRecordsInOrderThenTimesOut(t *testing.T) {
	c := New(collector.Info{Kernel: "x"}, &collector.Snapshot{StartNS: 1})
	c.Push(collector.Event{Kind: collector.KindFork, BootNS: 1}, collector.Event{Kind: collector.KindExit, BootNS: 2})
	for i, want := range []collector.Kind{collector.KindFork, collector.KindExit} {
		ev, err := c.Next(time.Now().Add(time.Second))
		if err != nil || ev.Kind != want {
			t.Fatalf("record %d: %v %v", i, ev.Kind, err)
		}
	}
	start := time.Now()
	if _, err := c.Next(time.Now().Add(30 * time.Millisecond)); err != collector.ErrTimeout || time.Since(start) < 20*time.Millisecond {
		t.Fatalf("expected a timeout after waiting: %v", err)
	}
	// A record pushed while Next waits wakes it up.
	go func() { time.Sleep(10 * time.Millisecond); c.Push(collector.Event{BootNS: 7}) }()
	if ev, err := c.Next(time.Now().Add(2 * time.Second)); err != nil || ev.BootNS != 7 {
		t.Fatalf("%v %v", ev, err)
	}
	c.Close()
	if _, err := c.Next(time.Now().Add(time.Second)); err != collector.ErrClosed {
		t.Fatalf("after Close: %v", err)
	}
}

func TestSnapshotsStatsAndLiveStart(t *testing.T) {
	s1, s2 := &collector.Snapshot{StartNS: 1}, &collector.Snapshot{StartNS: 2}
	c := New(collector.Info{}, s1, s2)
	if got, _ := c.Snapshot(); got != s1 {
		t.Error("first snapshot")
	}
	if got, _ := c.Snapshot(); got != s2 {
		t.Error("second snapshot")
	}
	if got, _ := c.Snapshot(); got != s2 {
		t.Error("the last snapshot repeats")
	}
	c.SetStats(collector.Stats{LostFork: 3})
	if st, _ := c.Stats(); st.Lost() != 3 {
		t.Error("stats")
	}
	c.SetLiveStart(5, 99)
	if v, _ := c.LiveStart(5); v != 99 {
		t.Error("live start")
	}
	if c.Stopped() {
		t.Error("not stopped yet")
	}
	c.StopCapture()
	if !c.Stopped() {
		t.Error("stopped")
	}
}
