package response

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/config"
	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/killrule"
)

// System is everything the worker needs from the operating system. The real
// implementation uses pidfd_open(2), pidfd_send_signal(2) and /proc; tests
// replace it to simulate pid reuse and errors.
type System interface {
	// PidfdOpen returns a handle for the process with the given tgid.
	PidfdOpen(tgid int) (int, error)
	// PidfdSignal sends sig through the handle to that one process (all its
	// threads, not its group or children). Signal 0 only probes.
	PidfdSignal(fd int, sig syscall.Signal) error
	Close(fd int) error
	// ExeLink is the target of /proc/<tgid>/exe.
	ExeLink(tgid int) (string, error)
	// Cmdline is the beginning of /proc/<tgid>/cmdline (at most max bytes) and
	// whether more data existed.
	Cmdline(tgid int, max int) ([]byte, bool, error)
	// BootNS is the current CLOCK_BOOTTIME.
	BootNS() uint64
	Now() time.Time
}

// Identity is the exact start time of the process that currently owns a tgid,
// from the same kernel field the collector uses (0 when none).
type Identity interface {
	LiveStart(tgid uint32) (uint64, error)
}

// Emitter writes audit events; it must be safe for concurrent use.
type Emitter interface {
	Emit(ev *event.Event) error
}

// Options configures a Worker.
type Options struct {
	Factory  *event.Factory
	Emitter  Emitter
	Rules    *killrule.Rules
	System   System
	Identity Identity
	DryRun   bool
	// ArgLimits are the argument capture limits; the re-check right before the
	// signal reads the arguments with the same limits as the capture did. The
	// zero value selects the defaults.
	ArgLimits collector.ArgLimits
	// OnFatal is called once when an audit event cannot be written. The worker
	// stops taking actions afterwards.
	OnFatal func(error)
}

// Counters are the numbers reported in agent.health.
type Counters struct {
	SignalAttempts   uint64
	SignalsAccepted  uint64
	AlreadyExited    uint64
	PermissionDenied uint64
	Errors           uint64
	DryRun           uint64
	Skipped          map[string]uint64
	QueueLen         int
	LatencyCount     uint64
	LatencyAvgNS     uint64
	LatencyMaxNS     uint64
}

// skipReasons are all reasons a worker can report; counters are kept per reason.
var skipReasons = []string{
	event.SkipIdentityUnverified, event.SkipIdentityMismatch, event.SkipMatchNoLongerVerif,
	event.SkipActionQueueFull, event.SkipShutdown, event.SkipLineageUnconfirmed, event.SkipActionsDisabled,
}

// Worker executes kill actions one at a time. The queue is bounded; nothing
// here spawns goroutines per action.
type Worker struct {
	o     Options
	queue chan *Action

	stopping atomic.Bool
	halted   atomic.Bool
	fatal    sync.Once
	quit     chan struct{}
	done     chan struct{}

	attempts, accepted, exited, denied, errs, dry atomic.Uint64
	skipped                                       map[string]*atomic.Uint64
	latN, latSum, latMax                          atomic.Uint64
}

// NewWorker creates the worker; call Start to run it.
func NewWorker(o Options) *Worker {
	w := &Worker{
		o:       o,
		queue:   make(chan *Action, QueueCap),
		quit:    make(chan struct{}),
		done:    make(chan struct{}),
		skipped: make(map[string]*atomic.Uint64, len(skipReasons)),
	}
	for _, r := range skipReasons {
		w.skipped[r] = new(atomic.Uint64)
	}
	return w
}

var _ Responder = (*Worker)(nil)

// Start launches the single worker goroutine.
func (w *Worker) Start() { go w.run() }

// Submit implements Responder: it never blocks.
func (w *Worker) Submit(a *Action) {
	switch {
	case w.stopping.Load():
		w.finish(a, Result{Outcome: event.OutcomeSkipped, Reason: event.SkipShutdown})
	case w.halted.Load():
		w.finish(a, Result{Outcome: event.OutcomeSkipped, Reason: event.SkipActionsDisabled})
	case a.DryRun:
		w.finish(a, Result{Outcome: event.OutcomeDryRun})
	default:
		select {
		case w.queue <- a:
		default:
			w.finish(a, Result{Outcome: event.OutcomeSkipped, Reason: event.SkipActionQueueFull})
		}
	}
}

// Skip implements Responder: the action is recorded as skipped without being
// queued (there is no kill_requested event for it).
func (w *Worker) Skip(a *Action, reason string) {
	w.finish(a, Result{Outcome: event.OutcomeSkipped, Reason: reason})
}

// Stop ends the intake, completes everything still waiting as skipped
// (shutdown) and waits until the running action has finished or ctx is done.
// Call it after the last Submit (the process model has stopped delivering).
func (w *Worker) Stop(ctx context.Context) {
	if w.stopping.Swap(true) {
		return
	}
	close(w.quit)
	select {
	case <-w.done:
	case <-ctx.Done():
	}
}

// Counters returns the current numbers.
func (w *Worker) Counters() Counters {
	c := Counters{
		SignalAttempts:   w.attempts.Load(),
		SignalsAccepted:  w.accepted.Load(),
		AlreadyExited:    w.exited.Load(),
		PermissionDenied: w.denied.Load(),
		Errors:           w.errs.Load(),
		DryRun:           w.dry.Load(),
		Skipped:          make(map[string]uint64, len(w.skipped)),
		QueueLen:         len(w.queue),
		LatencyCount:     w.latN.Load(),
		LatencyMaxNS:     w.latMax.Load(),
	}
	for r, n := range w.skipped {
		c.Skipped[r] = n.Load()
	}
	if c.LatencyCount > 0 {
		c.LatencyAvgNS = w.latSum.Load() / c.LatencyCount
	}
	return c
}

func (w *Worker) run() {
	defer close(w.done)
	for {
		select {
		case a := <-w.queue:
			w.handle(a)
		case <-w.quit:
			// Everything still waiting is completed as skipped; nothing new is started.
			for {
				select {
				case a := <-w.queue:
					w.finish(a, Result{Outcome: event.OutcomeSkipped, Reason: event.SkipShutdown})
				default:
					return
				}
			}
		}
	}
}

func (w *Worker) handle(a *Action) {
	switch {
	case w.halted.Load():
		w.finish(a, Result{Outcome: event.OutcomeSkipped, Reason: event.SkipActionsDisabled})
	case w.stopping.Load():
		w.finish(a, Result{Outcome: event.OutcomeSkipped, Reason: event.SkipShutdown})
	default:
		w.finish(a, w.execute(a))
	}
}

// execute is the five step kill procedure. It returns the
// result; the pidfd is closed on every path.
func (w *Worker) execute(a *Action) Result {
	sys := w.o.System

	// Cheap checks against the event stream: a newer exec or an observed exit
	// change what the decision was based on.
	if r, stop := w.stale(a); stop {
		return r
	}

	fd, err := sys.PidfdOpen(int(a.Key.TGID))
	if err != nil {
		return w.openError(err)
	}
	defer sys.Close(fd)

	// Step 3: the exact identity. The pidfd was opened first: from here on the
	// signal can only reach the process that owned the pid at that moment, so it
	// is enough to prove that this process is the expected one.
	start, err := w.o.Identity.LiveStart(a.Key.TGID)
	switch {
	case err != nil:
		return Result{Outcome: event.OutcomeSkipped, Reason: event.SkipIdentityUnverified, Err: sysError("identity", err)}
	case start == 0:
		// No process owns the tgid according to the hooks. Probe the handle:
		// a dead process is the expected outcome, anything else is unproven.
		if perr := sys.PidfdSignal(fd, 0); errors.Is(perr, syscall.ESRCH) {
			return Result{Outcome: event.OutcomeAlreadyExited}
		}
		return Result{Outcome: event.OutcomeSkipped, Reason: event.SkipIdentityUnverified}
	case start != a.Key.StartNS:
		return Result{Outcome: event.OutcomeSkipped, Reason: event.SkipIdentityMismatch}
	}

	// Step 4: current values of the matched fields, as far as they can be read.
	if r, stop := w.recheck(a); stop {
		return r
	}
	if r, stop := w.stale(a); stop {
		return r
	}

	// Step 5: the signal goes through the verified handle and nowhere else.
	attempted := sys.Now().UTC()
	attemptBoot := sys.BootNS()
	w.attempts.Add(1)
	res := Result{AttemptedAt: attempted, AttemptBootNS: attemptBoot}
	switch err := sys.PidfdSignal(fd, syscall.SIGKILL); {
	case err == nil:
		res.Outcome = event.OutcomeSignalSent
	case errors.Is(err, syscall.ESRCH):
		res.Outcome = event.OutcomeAlreadyExited
	case errors.Is(err, syscall.EPERM):
		res.Outcome = event.OutcomePermissionDenied
		res.Err = sysError("pidfd_send_signal", err)
	default:
		res.Outcome = event.OutcomeError
		res.Err = sysError("pidfd_send_signal", err)
	}
	return res
}

func (w *Worker) stale(a *Action) (Result, bool) {
	if a.Live == nil {
		return Result{}, false
	}
	if !a.Live.Alive.Load() {
		return Result{Outcome: event.OutcomeAlreadyExited}, true
	}
	if int(a.Live.ExecIndex.Load()) != a.ExecIndex {
		// The process executed another program in the meantime; that exec is
		// judged by its own decision.
		return Result{Outcome: event.OutcomeSkipped, Reason: event.SkipMatchNoLongerVerif}, true
	}
	return Result{}, false
}

func (w *Worker) openError(err error) Result {
	switch {
	case errors.Is(err, syscall.ESRCH):
		return Result{Outcome: event.OutcomeAlreadyExited}
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
		return Result{Outcome: event.OutcomePermissionDenied, Err: sysError("pidfd_open", err)}
	default: // EMFILE, ENFILE, ENOMEM, ENOSYS, EINVAL: reported, never retried
		return Result{Outcome: event.OutcomeError, Err: sysError("pidfd_open", err)}
	}
}

// recheck reads the current executable and arguments and requires that at
// least one of the original hits still holds. Fields that cannot be read prove
// nothing; a vanished process is a normal outcome.
func (w *Worker) recheck(a *Action) (Result, bool) {
	sys := w.o.System
	pid := int(a.Key.TGID)
	var image, imgPath *string
	var argv []string

	needExe, needArgv := false, false
	for _, h := range a.Hits {
		switch h.Field {
		case config.KillFieldImage, config.KillFieldImagePath:
			needExe = true
		case config.KillFieldArgv:
			needArgv = true
		}
	}
	if needExe {
		link, err := sys.ExeLink(pid)
		switch {
		case err == nil:
			image, imgPath = currentExe(link, a.Process != nil && a.Process.ImageDeleted != nil && *a.Process.ImageDeleted)
		case isGone(err):
			return Result{Outcome: event.OutcomeAlreadyExited}, true
		}
	}
	if needArgv {
		lim := w.o.ArgLimits.Normalized()
		raw, more, err := sys.Cmdline(pid, lim.MaxBytes)
		switch {
		case err == nil:
			argv = collector.ParseArgs(raw, more, 0, 0, lim).List
		case isGone(err):
			return Result{Outcome: event.OutcomeAlreadyExited}, true
		}
	}
	if len(w.o.Rules.Retest(a.Hits, image, imgPath, argv)) == 0 {
		return Result{Outcome: event.OutcomeSkipped, Reason: event.SkipMatchNoLongerVerif}, true
	}
	return Result{}, false
}

// currentExe splits the /proc/<pid>/exe link target into image and path. The
// kernel appends " (deleted)" for unlinked files, which is ambiguous with a
// file literally named so: the path is only used when the original record
// agrees that the file was deleted.
func currentExe(link string, originallyDeleted bool) (image, imgPath *string) {
	deleted := strings.HasSuffix(link, " (deleted)")
	trimmed := strings.TrimSuffix(link, " (deleted)")
	base := path.Base(trimmed)
	image = &base
	if deleted == originallyDeleted {
		imgPath = &trimmed
	}
	return image, imgPath
}

func isGone(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH)
}

func sysError(op string, err error) *event.SysError {
	se := &event.SysError{Op: op, Message: err.Error()}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		se.Code = int(errno)
		se.Errno = errnoName(errno)
	} else {
		se.Errno = "UNKNOWN"
	}
	return se
}

func errnoName(e syscall.Errno) string {
	switch e {
	case syscall.ESRCH:
		return "ESRCH"
	case syscall.EPERM:
		return "EPERM"
	case syscall.EACCES:
		return "EACCES"
	case syscall.EMFILE:
		return "EMFILE"
	case syscall.ENFILE:
		return "ENFILE"
	case syscall.ENOMEM:
		return "ENOMEM"
	case syscall.EINVAL:
		return "EINVAL"
	case syscall.ENOSYS:
		return "ENOSYS"
	case syscall.EAGAIN:
		return "EAGAIN"
	case syscall.ENOENT:
		return "ENOENT"
	}
	return fmt.Sprintf("errno_%d", int(e))
}

// finish writes the result event and updates the counters. A write error
// stops all further actions.
func (w *Worker) finish(a *Action, r Result) {
	switch r.Outcome {
	case event.OutcomeSignalSent:
		w.accepted.Add(1)
	case event.OutcomeAlreadyExited:
		w.exited.Add(1)
	case event.OutcomePermissionDenied:
		w.denied.Add(1)
	case event.OutcomeError:
		w.errs.Add(1)
	case event.OutcomeDryRun:
		w.dry.Add(1)
	case event.OutcomeSkipped:
		if c, ok := w.skipped[r.Reason]; ok {
			c.Add(1)
		}
	}
	if !r.AttemptedAt.IsZero() {
		lat := uint64(0)
		if r.AttemptBootNS > a.TriggerBootNS {
			lat = r.AttemptBootNS - a.TriggerBootNS
		}
		w.latN.Add(1)
		w.latSum.Add(lat)
		for {
			cur := w.latMax.Load()
			if lat <= cur || w.latMax.CompareAndSwap(cur, lat) {
				break
			}
		}
	}
	ev := NewKillEvent(w.o.Factory, a, event.TypeKillResult, r)
	if err := w.o.Emitter.Emit(ev); err != nil {
		w.halted.Store(true)
		w.fatal.Do(func() {
			if w.o.OnFatal != nil {
				w.o.OnFatal(err)
			}
		})
	}
}
