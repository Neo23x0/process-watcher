//go:build linux

// Package ebpf is the Linux collector: it loads the embedded CO-RE programs,
// attaches the fork/exec/exit hooks and reads the records and snapshots.
package ebpf

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/Neo23x0/process-watcher/internal/clock"
	"github.com/Neo23x0/process-watcher/internal/collector"
)

// Collector implements collector.Collector on top of eBPF.
type Collector struct {
	opts collector.Options
	info collector.Info

	objs  pwObjects
	links []link.Link
	rd    *ringbuf.Reader
	rec   ringbuf.Record

	liveSize uint32

	// Several threads can observe signal->live == 0 at the same moment when a
	// multi-threaded process dies, so one process may produce more than one
	// exit record. Only the first is returned.
	exits       map[collector.Key]struct{}
	exitRing    [exitRingSize]collector.Key
	exitNext    int
	duplicateEx uint64

	snapMu    sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

var _ collector.Collector = (*Collector)(nil)

// exitRingSize bounds the memory of recent exits kept for deduplication. The
// duplicates are emitted within microseconds of the first record.
const exitRingSize = 1024

// New loads the programs, attaches all hooks and starts buffering records. It
// returns a *collector.PrerequisiteError when the kernel, the permissions or
// the environment do not meet the requirements.
func New(opts collector.Options) (*Collector, error) {
	if err := checkEnvironment(); err != nil {
		return nil, err
	}
	if opts.RingBufferBytes <= 0 || opts.RingBufferBytes&(opts.RingBufferBytes-1) != 0 {
		return nil, fmt.Errorf("ring buffer size %d is not a power of two", opts.RingBufferBytes)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, &collector.PrerequisiteError{
			Check:  "memlock",
			Detail: "cannot lift RLIMIT_MEMLOCK for the BPF objects; run as root or grant CAP_SYS_RESOURCE",
			Err:    err,
		}
	}
	if err := checkKernelBTF(); err != nil {
		return nil, err
	}

	spec, err := loadPw()
	if err != nil {
		return nil, err
	}
	spec.Maps[pwMapPwEvents].MaxEntries = uint32(opts.RingBufferBytes)
	setVar := func(name string, v uint32) error {
		vs, ok := spec.Variables[name]
		if !ok {
			return fmt.Errorf("object has no variable %q", name)
		}
		return vs.Set(v)
	}
	opts.ArgLimits = opts.ArgLimits.Normalized()
	if opts.CaptureArgs {
		if lim := opts.ArgLimits; lim.MaxBytes < collector.MinMaxArgBytes || lim.MaxBytes > collector.CeilingMaxArgBytes ||
			lim.MaxArgs < collector.MinMaxArgs || lim.MaxArgs > collector.CeilingMaxArgs {
			return nil, fmt.Errorf("argument capture limits %d arguments / %d bytes are outside %d..%d arguments / %d..%d bytes",
				lim.MaxArgs, lim.MaxBytes, collector.MinMaxArgs, collector.CeilingMaxArgs, collector.MinMaxArgBytes, collector.CeilingMaxArgBytes)
		}
	}
	c := &Collector{opts: opts, exits: make(map[collector.Key]struct{}, exitRingSize)}
	if opts.CaptureArgs {
		if err := setVar(pwVarCfgCaptureArgs, 1); err != nil {
			return nil, err
		}
		if err := setVar(pwVarCfgArgsMax, uint32(opts.ArgLimits.MaxBytes)); err != nil {
			return nil, err
		}
	}
	if opts.LiveTable {
		pidMax, err := readPidMax()
		if err != nil {
			return nil, err
		}
		c.liveSize = pidMax
		spec.Maps[pwMapPwLive].MaxEntries = pidMax
		if err := setVar(pwVarCfgLiveTable, 1); err != nil {
			return nil, err
		}
		if err := setVar(pwVarCfgLiveSize, pidMax); err != nil {
			return nil, err
		}
	}

	if err := spec.LoadAndAssign(&c.objs, nil); err != nil {
		return nil, classifyLoadError(err)
	}

	// Attach in reverse lifecycle order: every process whose fork is seen is
	// then also covered by the exec and exit hooks.
	for _, h := range []struct {
		name string
		prog *cebpf.Program
	}{
		{"sched_process_exit", c.objs.PwSchedProcessExit},
		{"sched_process_exec", c.objs.PwSchedProcessExec},
		{"sched_process_fork", c.objs.PwSchedProcessFork},
	} {
		l, err := link.AttachTracing(link.TracingOptions{Program: h.prog})
		if err != nil {
			_ = c.Close()
			return nil, classifyLoadError(fmt.Errorf("attach tp_btf/%s: %w", h.name, err))
		}
		c.links = append(c.links, l)
	}
	c.info = collector.Info{
		Arch:          runtime.GOARCH,
		RingBytes:     opts.RingBufferBytes,
		HooksActiveNS: clock.BootNS(),
		CaptureArgs:   opts.CaptureArgs,
		ArgLimits:     opts.ArgLimits,
		LiveTable:     opts.LiveTable,
	}
	var uts unix.Utsname
	if unix.Uname(&uts) == nil {
		c.info.Kernel = unix.ByteSliceToString(uts.Release[:])
	}

	rd, err := ringbuf.NewReader(c.objs.PwEvents)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("open ring buffer reader: %w", err)
	}
	c.rd = rd
	return c, nil
}

// Next implements collector.Collector.
func (c *Collector) Next(deadline time.Time) (collector.Event, error) {
	for {
		c.rd.SetDeadline(deadline)
		if err := c.rd.ReadInto(&c.rec); err != nil {
			switch {
			case errors.Is(err, os.ErrDeadlineExceeded):
				return collector.Event{}, collector.ErrTimeout
			case errors.Is(err, ringbuf.ErrClosed):
				return collector.Event{}, collector.ErrClosed
			}
			return collector.Event{}, fmt.Errorf("read ring buffer: %w", err)
		}
		ev, err := decode(c.rec.RawSample, c.opts.ArgLimits)
		if err != nil {
			return collector.Event{}, err
		}
		if ev.Kind == collector.KindExit && c.duplicateExit(ev.Proc) {
			continue
		}
		return ev, nil
	}
}

// duplicateExit remembers the last exitRingSize exited instances.
func (c *Collector) duplicateExit(k collector.Key) bool {
	if _, dup := c.exits[k]; dup {
		c.duplicateEx++
		return true
	}
	delete(c.exits, c.exitRing[c.exitNext])
	c.exitRing[c.exitNext] = k
	c.exits[k] = struct{}{}
	c.exitNext = (c.exitNext + 1) % exitRingSize
	return false
}

// Pending implements collector.Collector.
func (c *Collector) Pending() int { return c.rd.AvailableBytes() }

// Snapshot implements collector.Collector.
func (c *Collector) Snapshot() (*collector.Snapshot, error) {
	c.snapMu.Lock() // the iterator uses per-CPU scratch space: one at a time
	defer c.snapMu.Unlock()

	it, err := link.AttachIter(link.IterOptions{Program: c.objs.PwDumpTask})
	if err != nil {
		return nil, fmt.Errorf("attach task iterator: %w", err)
	}
	defer it.Close()

	start := clock.BootNS()
	r, err := it.Open()
	if err != nil {
		return nil, fmt.Errorf("open task iterator: %w", err)
	}
	defer r.Close()
	procs, err := decodeSnapshot(r)
	if err != nil {
		return nil, fmt.Errorf("read task iterator: %w", err)
	}
	return &collector.Snapshot{StartNS: start, EndNS: clock.BootNS(), Procs: procs}, nil
}

// Stats implements collector.Collector.
func (c *Collector) Stats() (collector.Stats, error) {
	var vals [statMax]uint64
	for i := range vals {
		var perCPU []uint64
		if err := c.objs.PwStats.Lookup(uint32(i), &perCPU); err != nil {
			return collector.Stats{}, fmt.Errorf("read counter %d: %w", i, err)
		}
		for _, v := range perCPU {
			vals[i] += v
		}
	}
	return collector.Stats{
		LostFork: vals[statLostFork], LostExec: vals[statLostExec], LostExit: vals[statLostExit],
		Fork: vals[statFork], Exec: vals[statExec], Exit: vals[statExit],
		ThreadClones:   vals[statThreadClone],
		KernelThreads:  vals[statKThread],
		ThreadExits:    vals[statThreadExit],
		LiveOutOfRange: vals[statLiveOOR],
		ScratchErrors:  vals[statScratch],
		ArgsErrors:     vals[statArgsErr],
		PathErrors:     vals[statPathErr],
		DuplicateExits: c.duplicateEx,
	}, nil
}

// LiveStart implements collector.Collector.
func (c *Collector) LiveStart(tgid uint32) (uint64, error) {
	if !c.opts.LiveTable {
		return 0, errors.New("live table not enabled")
	}
	if tgid >= c.liveSize {
		return 0, fmt.Errorf("tgid %d is beyond the live table (%d entries, pid_max was raised?)", tgid, c.liveSize)
	}
	var start uint64
	if err := c.objs.PwLive.Lookup(tgid, &start); err != nil {
		return 0, fmt.Errorf("read live table: %w", err)
	}
	return start, nil
}

// Info implements collector.Collector.
func (c *Collector) Info() collector.Info { return c.info }

// StopCapture implements collector.Collector.
func (c *Collector) StopCapture() error {
	var errs []error
	for _, l := range c.links {
		errs = append(errs, l.Close())
	}
	c.links = nil
	return errors.Join(errs...)
}

// Close implements collector.Collector. It is safe to call more than once.
func (c *Collector) Close() error {
	c.closeOnce.Do(func() {
		var errs []error
		if c.rd != nil {
			errs = append(errs, c.rd.Close())
		}
		errs = append(errs, c.StopCapture())
		errs = append(errs, c.objs.Close())
		c.closeErr = errors.Join(errs...)
	})
	return c.closeErr
}

func readPidMax() (uint32, error) {
	b, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		return 0, fmt.Errorf("read pid_max: %w", err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("parse pid_max %q: %v", strings.TrimSpace(string(b)), err)
	}
	return uint32(n), nil
}
