// Package replay is a deterministic collector.Collector for tests: it returns
// scripted records and snapshots instead of reading the kernel, so the process
// model and the application can be tested without eBPF and on any platform.
package replay

import (
	"sync"
	"time"

	"github.com/Neo23x0/process-watcher/internal/collector"
)

// Collector replays what the test pushes into it.
type Collector struct {
	mu        sync.Mutex
	cond      *sync.Cond
	queue     []collector.Event
	snapshots []*collector.Snapshot
	snapFn    func() (*collector.Snapshot, error)
	stats     collector.Stats
	statsFn   func() collector.Stats
	statsErr  error
	liveStart map[uint32]uint64
	info      collector.Info
	opts      collector.Options
	closed    bool
	stopped   bool
	nextCalls int
}

var _ collector.Collector = (*Collector)(nil)

// New creates a replay collector. The initial snapshot is returned by the
// first Snapshot call; later calls return the following snapshots and finally
// repeat the last one.
func New(info collector.Info, snapshots ...*collector.Snapshot) *Collector {
	c := &Collector{info: info, snapshots: snapshots, liveStart: map[uint32]uint64{}}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// SetOptions records the options the collector was opened with.
func (c *Collector) SetOptions(o collector.Options) {
	c.mu.Lock()
	c.opts = o
	c.mu.Unlock()
}

// Options returns the options the collector was opened with.
func (c *Collector) Options() collector.Options {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.opts
}

// Push appends records to the stream Next returns.
func (c *Collector) Push(evs ...collector.Event) {
	c.mu.Lock()
	c.queue = append(c.queue, evs...)
	c.mu.Unlock()
	c.cond.Broadcast()
}

// SetSnapshotFunc makes Snapshot call fn instead of using the scripted list.
func (c *Collector) SetSnapshotFunc(fn func() (*collector.Snapshot, error)) {
	c.mu.Lock()
	c.snapFn = fn
	c.mu.Unlock()
}

// AddSnapshot queues another snapshot.
func (c *Collector) AddSnapshot(s *collector.Snapshot) {
	c.mu.Lock()
	c.snapshots = append(c.snapshots, s)
	c.mu.Unlock()
}

// SetStats replaces the kernel counters returned by Stats.
func (c *Collector) SetStats(s collector.Stats) {
	c.mu.Lock()
	c.stats = s
	c.mu.Unlock()
}

// SetStatsFunc makes Stats call fn.
func (c *Collector) SetStatsFunc(fn func() collector.Stats) {
	c.mu.Lock()
	c.statsFn = fn
	c.mu.Unlock()
}

// SetStatsError makes Stats fail with err until it is called again with nil.
func (c *Collector) SetStatsError(err error) {
	c.mu.Lock()
	c.statsErr = err
	c.mu.Unlock()
}

// SetLiveStart sets the live table entry of a tgid.
func (c *Collector) SetLiveStart(tgid uint32, start uint64) {
	c.mu.Lock()
	c.liveStart[tgid] = start
	c.mu.Unlock()
}

// Stopped reports whether StopCapture was called.
func (c *Collector) Stopped() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopped
}

// Next implements collector.Collector.
func (c *Collector) Next(deadline time.Time) (collector.Event, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextCalls++
	for len(c.queue) == 0 {
		if c.closed {
			return collector.Event{}, collector.ErrClosed
		}
		wait := time.Until(deadline)
		if wait <= 0 {
			return collector.Event{}, collector.ErrTimeout
		}
		timer := time.AfterFunc(wait, func() { c.cond.Broadcast() })
		c.cond.Wait()
		timer.Stop()
		if len(c.queue) == 0 && !time.Now().Before(deadline) {
			return collector.Event{}, collector.ErrTimeout
		}
	}
	ev := c.queue[0]
	c.queue = c.queue[1:]
	return ev, nil
}

// Pending implements collector.Collector: a rough byte count of queued records.
func (c *Collector) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.queue) * 128
}

// Snapshot implements collector.Collector.
func (c *Collector) Snapshot() (*collector.Snapshot, error) {
	c.mu.Lock()
	fn := c.snapFn
	c.mu.Unlock()
	if fn != nil {
		return fn()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case len(c.snapshots) == 0:
		return &collector.Snapshot{}, nil
	case len(c.snapshots) == 1:
		return c.snapshots[0], nil
	}
	s := c.snapshots[0]
	c.snapshots = c.snapshots[1:]
	return s, nil
}

// Stats implements collector.Collector.
func (c *Collector) Stats() (collector.Stats, error) {
	c.mu.Lock()
	fn, s, serr := c.statsFn, c.stats, c.statsErr
	c.mu.Unlock()
	if serr != nil {
		return collector.Stats{}, serr
	}
	if fn != nil {
		return fn(), nil
	}
	return s, nil
}

// LiveStart implements collector.Collector.
func (c *Collector) LiveStart(tgid uint32) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.liveStart[tgid], nil
}

// Info implements collector.Collector.
func (c *Collector) Info() collector.Info { return c.info }

// StopCapture implements collector.Collector.
func (c *Collector) StopCapture() error {
	c.mu.Lock()
	c.stopped = true
	c.mu.Unlock()
	return nil
}

// Close implements collector.Collector.
func (c *Collector) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.cond.Broadcast()
	return nil
}
