// Package proctree is the process model: it turns the ordered fork/exec/exit
// records and snapshots of the collector into the events of the observed
// process trees.
//
// All state lives in one goroutine (the caller of HandleEvent and
// ApplySnapshot); only the response.Liveness values of instances are shared
// with the kill worker, through atomics.
package proctree

import (
	"strconv"

	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/filter"
	"github.com/Neo23x0/process-watcher/internal/killrule"
	"github.com/Neo23x0/process-watcher/internal/response"
)

// Emitter receives every event the engine produces. An error is fatal: the
// local log is mandatory.
type Emitter interface {
	Emit(ev *event.Event) error
}

// Options configures an Engine.
type Options struct {
	Factory *event.Factory
	Emitter Emitter

	Matcher    *filter.Matcher    // watch patterns, required
	Exclusions *filter.Exclusions // nil: no exclusions
	MaxDepth   int                // limits emitted events only, 0 = unlimited
	// MaxProcesses bounds the retained instances (alive ones and the ancestors
	// still needed by them).
	MaxProcesses int
	CaptureArgv  bool

	// Kill enables the response feature when non-nil.
	Kill      *killrule.Rules
	DryRun    bool
	Responder response.Responder
	// AgentPID is never a kill target.
	AgentPID uint32

	// SnapshotArgs reads the arguments of a process found by the snapshot; it
	// must verify that the process is still the given instance. Optional.
	SnapshotArgs func(collector.Key) collector.Args
}

// Notice is something the application should report as agent.gap.
type Notice struct {
	Cause  string
	Detail string
}

// Stats are the engine counters for agent.health.
type Stats struct {
	Roots     int // living roots
	Instances int // living tracked instances
	Retained  int // living plus still referenced ancestors
	GapOpen   bool

	Discovered, Forks, Execs, Exits, InferredExits uint64
	DepthSuppressed                                uint64
	TableFull                                      uint64
	DuplicateBirths                                uint64
	KillHits                                       uint64
	KillIneligible                                 uint64
}

// Engine is the process model.
type Engine struct {
	o        Options
	inst     map[collector.Key]*Instance
	retained int
	roots    int
	gapOpen  bool
	stats    Stats
	notices  []Notice
	fullSent bool

	// wantReconcile is set when a root was admitted by a live exec: living
	// processes that already were its children cannot be known from records and
	// are found by the next snapshot.
	wantReconcile bool
	killDisabled  bool
}

// New creates an engine.
func New(o Options) *Engine {
	if o.Exclusions == nil {
		o.Exclusions = filter.NewExclusions(nil, nil, false)
	}
	if o.Responder == nil {
		o.Responder = nopResponder{}
	}
	return &Engine{o: o, inst: make(map[collector.Key]*Instance)}
}

type nopResponder struct{}

func (nopResponder) Submit(*response.Action)       {}
func (nopResponder) Skip(*response.Action, string) {}

// Stats returns the current counters.
func (e *Engine) Stats() Stats {
	s := e.stats
	s.Roots = e.roots
	s.Instances = len(e.inst)
	s.Retained = e.retained
	s.GapOpen = e.gapOpen
	return s
}

// TakeNotices returns and clears the pending gap notices.
func (e *Engine) TakeNotices() []Notice {
	n := e.notices
	e.notices = nil
	return n
}

// TakeReconcileHint reports (once) that a root was admitted at runtime and a
// snapshot should discover its already living descendants soon.
func (e *Engine) TakeReconcileHint() bool {
	h := e.wantReconcile
	e.wantReconcile = false
	return h
}

// DisableKill stops the creation of kill decisions (shutdown): no new action
// is started or recorded after this call.
func (e *Engine) DisableKill() { e.killDisabled = true }

// MarkGap records that records were lost. The next completed reconciliation
// closes the gap; instances it admits are marked as gap affected.
func (e *Engine) MarkGap() { e.gapOpen = true }

// GapOpen reports whether a loss was recorded since the last reconciliation.
func (e *Engine) GapOpen() bool { return e.gapOpen }

// Lookup returns the living instance for key, or nil.
func (e *Engine) Lookup(k collector.Key) *Instance { return e.inst[k] }

// HandleEvent processes one live record in ring order.
func (e *Engine) HandleEvent(ev collector.Event) error {
	switch ev.Kind {
	case collector.KindFork:
		return e.onFork(ev)
	case collector.KindExec:
		return e.onExec(ev)
	case collector.KindExit:
		return e.onExit(ev)
	}
	return nil
}

func (e *Engine) onFork(ev collector.Event) error {
	parent := e.inst[ev.Parent]
	if parent == nil {
		return nil // creator is not part of any observed tree
	}
	if _, known := e.inst[ev.Proc]; known {
		// The snapshot saw the child a moment before its fork record arrived.
		e.stats.DuplicateBirths++
		return nil
	}
	if !e.hasRoom() {
		return nil
	}
	i := e.newInstance(ev.Proc, ev.BootNS)
	i.Role = event.RoleDescendant
	i.Depth = parent.Depth + 1
	i.Root = parent.Root
	i.Parent = parent
	parent.refs++
	i.parentOut = e.parentOf(parent, event.RelFork)
	i.GapAffected = parent.GapAffected

	// A new process starts with its creator's image and arguments.
	i.Image, i.ImageOK, i.ImageTruncated = parent.Image, parent.ImageOK, parent.ImageTruncated
	i.Path = parent.Path
	i.ImageState = event.StateInherited
	i.Args, i.ArgsState = parent.Args, parent.ArgsState
	if e.o.CaptureArgv && i.ArgsState != "" {
		i.ArgsState = event.StateInherited
	}
	i.Comm, i.UID, i.EUID, i.GID = ev.Comm, ev.UID, ev.EUID, ev.GID

	pev := e.o.Factory.NewAt(event.TypeProcessFork, event.SourceEBPF, ev.BootNS)
	e.fill(pev, i)
	pev.Details = &event.ForkDetails{CreatorTID: ev.TID}
	e.stats.Forks++
	if err := e.emitProcess(pev, i); err != nil {
		return err
	}
	return e.evalKill(i, pev, ev.BootNS, true)
}

func (e *Engine) onExec(ev collector.Event) error {
	i := e.inst[ev.Proc]
	if i == nil {
		return e.onUnknownExec(ev)
	}
	if i.visitNS != 0 && ev.BootNS <= i.visitNS {
		// The snapshot record of this instance was taken after this exec, so
		// the discovered state already is the result of it.
		return nil
	}
	var prev *string
	if i.ImageOK {
		p, _ := event.Sanitize(i.Image)
		prev = &p
	}
	e.applyExec(i, ev)

	pev := e.o.Factory.NewAt(event.TypeProcessExec, event.SourceEBPF, ev.BootNS)
	e.fill(pev, i)
	pev.Details = e.execDetails(i, ev, prev)
	e.stats.Execs++
	if err := e.emitProcess(pev, i); err != nil {
		return err
	}
	return e.evalKill(i, pev, ev.BootNS, false)
}

// onUnknownExec handles the exec of an instance the engine does not track. It
// becomes a root when the new image matches a watch pattern. When its real
// parent is an observed process the fork record was missed: it is attached to
// that tree whatever its image is, but marked as not backed by a fork record.
func (e *Engine) onUnknownExec(ev collector.Event) error {
	x := ev.Exec
	parent := e.inst[ev.Parent]
	if parent == nil && (!x.ImageOK || !e.o.Matcher.Match(x.Image)) {
		return nil
	}
	if !e.hasRoom() {
		return nil
	}
	i := e.newInstance(ev.Proc, ev.BootNS)
	if parent != nil {
		// Its real parent is observed, so the fork record was missed: attach it
		// to that tree but mark the relation as not backed by a fork record.
		i.Role = event.RoleDescendant
		i.Depth = parent.Depth + 1
		i.Root = parent.Root
		i.Parent = parent
		parent.refs++
		i.parentOut = e.parentOf(parent, event.RelExecParent)
		i.GapAffected = true
	} else {
		e.makeRoot(i, x.Image, x.ImageOK)
		e.wantReconcile = true
		if !ev.Parent.IsZero() {
			po := &event.Parent{
				ProcessID:          event.ProcessID(e.bootID(), ev.Parent.TGID, ev.Parent.StartNS),
				PID:                ev.Parent.TGID,
				Image:              optStr(x.ParentImage, x.ParentImage != ""),
				RelationshipSource: event.RelExecParent,
			}
			i.parentOut = po
		} else {
			i.parentUnknown = true
		}
	}
	e.applyExec(i, ev)

	pev := e.o.Factory.NewAt(event.TypeProcessExec, event.SourceEBPF, ev.BootNS)
	e.fill(pev, i)
	pev.Details = e.execDetails(i, ev, nil)
	e.stats.Execs++
	if err := e.emitProcess(pev, i); err != nil {
		return err
	}
	return e.evalKill(i, pev, ev.BootNS, false)
}

func (e *Engine) applyExec(i *Instance, ev collector.Event) {
	x := ev.Exec
	i.Image, i.ImageOK, i.ImageTruncated = x.Image, x.ImageOK, x.ImageTruncated
	i.Path = x.Path
	i.ImageState = event.StateExecuted
	i.Comm, i.UID, i.EUID, i.GID = ev.Comm, ev.UID, ev.EUID, ev.GID
	if e.o.CaptureArgv {
		i.Args, i.ArgsState = x.Args, event.StateExecuted
	} else {
		i.Args, i.ArgsState = collector.Args{}, ""
	}
	i.ExecIndex++
	i.live.ExecIndex.Store(int32(i.ExecIndex))
}

func (e *Engine) execDetails(i *Instance, ev collector.Event, prev *string) *event.ExecDetails {
	d := &event.ExecDetails{ExecIndex: i.ExecIndex, PreviousImage: prev, ThreadExec: ev.Exec.FromThread}
	if ev.Exec.FilenameOK {
		s, _ := event.Sanitize(ev.Exec.Filename)
		d.ExecFilename = &s
	}
	return d
}

func (e *Engine) onExit(ev collector.Event) error {
	i := e.inst[ev.Proc]
	if i == nil {
		return nil
	}
	code, sig, core := decodeStatus(ev.ExitStatus)
	d := &event.ExitDetails{
		ExitCode: code, Signal: sig, CoreDumped: core,
		ExitSource: "kernel",
	}
	if i.ActionID != "" {
		d.ResponseActionID = event.Str(i.ActionID)
	}
	if ev.BootNS >= i.Key.StartNS {
		d.DurationNS = event.StrNS(ev.BootNS - i.Key.StartNS)
	}
	pev := e.o.Factory.NewAt(event.TypeProcessExit, event.SourceEBPF, ev.BootNS)
	e.fill(pev, i)
	pev.Details = d
	e.stats.Exits++
	err := e.emitProcess(pev, i)
	e.retire(i)
	return err
}

// decodeStatus splits a wait(2) style status. Values that cannot be known
// stay nil.
func decodeStatus(status int32) (code, sig *int, core *bool) {
	s := int(status) & 0x7f
	if s == 0 {
		c := (int(status) >> 8) & 0xff
		return &c, nil, nil
	}
	cd := status&0x80 != 0
	return nil, &s, &cd
}

// retire removes an instance that exited and releases what nobody needs.
func (e *Engine) retire(i *Instance) {
	i.alive = false
	i.live.Alive.Store(false)
	delete(e.inst, i.Key)
	if i.Role == event.RoleRoot {
		e.roots--
	}
	e.release(i)
}

// release drops instances that are dead and no longer referenced, walking up
// the parent chain.
func (e *Engine) release(i *Instance) {
	for i != nil && !i.alive && i.refs == 0 && !i.released {
		i.released = true
		e.retained--
		p := i.Parent
		if p != nil {
			p.refs--
		}
		i = p
	}
}

func (e *Engine) hasRoom() bool {
	if e.retained < e.o.MaxProcesses {
		return true
	}
	e.stats.TableFull++
	e.gapOpen = true
	if !e.fullSent {
		e.fullSent = true
		e.notices = append(e.notices, Notice{Cause: "process_table_full", Detail: "the process table reached runtime.max_processes; new processes are not tracked"})
	}
	return false
}

func (e *Engine) newInstance(k collector.Key, knownSince uint64) *Instance {
	i := &Instance{
		Key:          k,
		ID:           event.ProcessID(e.bootID(), k.TGID, k.StartNS),
		alive:        true,
		killDoneExec: -1,
		knownSince:   knownSince,
	}
	i.live.Alive.Store(true)
	e.inst[k] = i
	e.retained++
	if e.fullSent && e.retained < e.o.MaxProcesses {
		e.fullSent = false
	}
	return i
}

func (e *Engine) bootID() string { return e.o.Factory.Host.BootID }

// makeRoot turns i into a tree root and remembers why it was admitted.
func (e *Engine) makeRoot(i *Instance, image string, ok bool) {
	i.Role = event.RoleRoot
	i.Depth = 0
	i.Root = i
	e.roots++
	if ok {
		s, _ := event.Sanitize(image)
		i.admitImage = &s
	}
	i.rootOut = &event.Root{ProcessID: i.ID, PID: i.Key.TGID, Image: i.admitImage}
}

func optStr(s string, ok bool) *string {
	if !ok {
		return nil
	}
	v, _ := event.Sanitize(s)
	return &v
}

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }
