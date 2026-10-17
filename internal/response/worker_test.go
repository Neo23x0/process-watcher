package response

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Neo23x0/process-watcher/internal/clock"
	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/config"
	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/killrule"
)

// fproc is one process instance in the simulated kernel.
type fproc struct {
	tgid     int
	start    uint64
	alive    bool
	exe      string
	cmdline  []byte
	signaled []syscall.Signal
}

// fakeKernel simulates what matters for the safety argument: a pidfd stays
// bound to the process it was opened for, even when the pid is handed to a
// new process later.
type fakeKernel struct {
	mu       sync.Mutex
	byPID    map[int]*fproc
	fds      map[int]*fproc
	nextFD   int
	opened   int
	closed   int
	openErr  error
	exeErr   error
	cmdErr   error
	probeErr error
	sigErr   error
	// hooks run at precise points of the worker, without holding mu.
	afterOpen    func()
	beforeSignal func()
	now          uint64
}

func newKernel() *fakeKernel {
	return &fakeKernel{byPID: map[int]*fproc{}, fds: map[int]*fproc{}, nextFD: 10, now: 5_000_000_000}
}

func (k *fakeKernel) spawn(tgid int, start uint64, exe, cmdline string) *fproc {
	k.mu.Lock()
	defer k.mu.Unlock()
	p := &fproc{tgid: tgid, start: start, alive: true, exe: exe, cmdline: []byte(cmdline)}
	k.byPID[tgid] = p
	return p
}

func (k *fakeKernel) die(p *fproc) {
	k.mu.Lock()
	defer k.mu.Unlock()
	p.alive = false
	if k.byPID[p.tgid] == p {
		delete(k.byPID, p.tgid)
	}
}

func (k *fakeKernel) PidfdOpen(tgid int) (int, error) {
	k.mu.Lock()
	if k.openErr != nil {
		k.mu.Unlock()
		return -1, k.openErr
	}
	p := k.byPID[tgid]
	if p == nil {
		k.mu.Unlock()
		return -1, syscall.ESRCH
	}
	fd := k.nextFD
	k.nextFD++
	k.fds[fd] = p
	k.opened++
	hook := k.afterOpen
	k.mu.Unlock()
	if hook != nil {
		hook()
	}
	return fd, nil
}

func (k *fakeKernel) PidfdSignal(fd int, sig syscall.Signal) error {
	k.mu.Lock()
	hook := k.beforeSignal
	k.mu.Unlock()
	if hook != nil && sig != 0 {
		hook()
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	p := k.fds[fd]
	if p == nil {
		return syscall.EBADF
	}
	if sig == 0 && k.probeErr != nil {
		return k.probeErr
	}
	if !p.alive {
		return syscall.ESRCH
	}
	if sig != 0 && k.sigErr != nil {
		return k.sigErr
	}
	if sig != 0 {
		p.signaled = append(p.signaled, sig)
		if sig == syscall.SIGKILL {
			p.alive = false
			if k.byPID[p.tgid] == p {
				delete(k.byPID, p.tgid)
			}
		}
	}
	return nil
}

func (k *fakeKernel) Close(fd int) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.fds, fd)
	k.closed++
	return nil
}

func (k *fakeKernel) ExeLink(tgid int) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.exeErr != nil {
		return "", k.exeErr
	}
	p := k.byPID[tgid]
	if p == nil {
		return "", syscall.ENOENT
	}
	return p.exe, nil
}

func (k *fakeKernel) Cmdline(tgid int, max int) ([]byte, bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cmdErr != nil {
		return nil, false, k.cmdErr
	}
	p := k.byPID[tgid]
	if p == nil {
		return nil, false, syscall.ENOENT
	}
	if len(p.cmdline) > max {
		return p.cmdline[:max], true, nil
	}
	return p.cmdline, false, nil
}

func (k *fakeKernel) BootNS() uint64 { k.mu.Lock(); defer k.mu.Unlock(); k.now += 1000; return k.now }
func (k *fakeKernel) Now() time.Time { return time.Date(2026, 10, 17, 12, 0, 1, 0, time.UTC) }

// LiveStart is the live table: the start time of the current owner of the tgid.
func (k *fakeKernel) LiveStart(tgid uint32) (uint64, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if p := k.byPID[int(tgid)]; p != nil {
		return p.start, nil
	}
	return 0, nil
}

type syncRecorder struct {
	mu     sync.Mutex
	events []*event.Event
	err    error
}

func (r *syncRecorder) Emit(ev *event.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, ev)
	return nil
}

func (r *syncRecorder) results() []*event.KillDetails {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*event.KillDetails
	for _, e := range r.events {
		if e.EventType == event.TypeKillResult {
			out = append(out, e.Details.(*event.KillDetails))
		}
	}
	return out
}

type rig struct {
	t    *testing.T
	k    *fakeKernel
	rec  *syncRecorder
	w    *Worker
	rule *killrule.Rules
	fat  chan error
}

func newRig(t *testing.T, dry bool, fields []string, strs, regexes []string) *rig {
	t.Helper()
	r := &rig{t: t, k: newKernel(), rec: &syncRecorder{}, fat: make(chan error, 1)}
	rules, err := killrule.Compile(config.KillConfig{Enabled: true, Fields: fields, Strings: strs, Regex: regexes})
	if err != nil {
		t.Fatal(err)
	}
	r.rule = rules
	n := 0
	fake := &clock.Fake{Boot: 5_000_000_000, Wall: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	r.w = NewWorker(Options{
		Factory: &event.Factory{
			AgentInstanceID: "agent", Host: event.Host{Hostname: "h", BootID: "b"}, Clock: fake,
			NewID: func() string { n++; return fmt.Sprintf("id-%d", n) },
		},
		Emitter: r.rec, Rules: rules, System: r.k, Identity: r.k, DryRun: dry,
		OnFatal: func(err error) { r.fat <- err },
	})
	return r
}

// action builds an action for p as the process model would: with the hits of
// the given subject.
func (r *rig) action(p *fproc, execIndex int, subj killrule.Subject) *Action {
	live := &Liveness{}
	live.Alive.Store(true)
	live.ExecIndex.Store(int32(execIndex))
	return &Action{
		ID: fmt.Sprintf("action-%d-%d", p.tgid, execIndex), TriggerEventID: "trigger", TriggerType: event.TypeProcessExec,
		TriggerBootNS: 4_999_999_000, DecidedAt: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC), DecidedBootNS: 5_000_000_000,
		Key: collector.Key{TGID: uint32(p.tgid), StartNS: p.start}, ExecIndex: execIndex,
		Hits: r.rule.Match(subj), Live: live,
		Process: &event.Process{ProcessID: "b:x", PID: uint32(p.tgid)}, Lineage: &event.Lineage{Role: event.RoleDescendant},
		DataQuality: event.DataQuality{},
	}
}

func sp(s string) *string { return &s }

// run executes one action synchronously through the worker's own code path.
func (r *rig) run(a *Action) *event.KillDetails {
	r.t.Helper()
	r.w.finish(a, r.w.execute(a))
	res := r.rec.results()
	if len(res) == 0 {
		r.t.Fatal("no result event")
	}
	return res[len(res)-1]
}

func TestSignalGoesThroughTheHandleAndKillsTheTarget(t *testing.T) {
	r := newRig(t, false, []string{"image"}, nil, []string{`^useradd$`})
	p := r.k.spawn(2000, 777, "/usr/sbin/useradd", "useradd\x00bob\x00")
	res := r.run(r.action(p, 1, killrule.Subject{Image: sp("useradd")}))

	if res.Outcome != event.OutcomeSignalSent || res.SignalAttemptedAt == nil || res.AttemptLatencyNS == nil {
		t.Fatalf("%+v", res)
	}
	if len(p.signaled) != 1 || p.signaled[0] != syscall.SIGKILL || p.alive {
		t.Errorf("signals %v alive=%v", p.signaled, p.alive)
	}
	if r.k.opened != 1 || r.k.closed != 1 {
		t.Errorf("handle opened %d closed %d", r.k.opened, r.k.closed)
	}
	if res.Signal != "SIGKILL" || res.Action != "kill" || res.ActionID != "action-2000-1" {
		t.Errorf("%+v", res)
	}
	c := r.w.Counters()
	if c.SignalAttempts != 1 || c.SignalsAccepted != 1 || c.LatencyCount != 1 || c.LatencyMaxNS == 0 {
		t.Errorf("counters %+v", c)
	}
}

func TestVanishedTargetIsAnExpectedOutcome(t *testing.T) {
	r := newRig(t, false, []string{"image"}, nil, []string{`^useradd$`})
	// Gone before the handle can be opened.
	gone := r.k.spawn(2001, 1, "/usr/sbin/useradd", "useradd\x00")
	r.k.die(gone)
	if res := r.run(r.action(gone, 1, killrule.Subject{Image: sp("useradd")})); res.Outcome != event.OutcomeAlreadyExited {
		t.Errorf("%+v", res)
	}
	// Dies between the identity check and the signal: the signal fails with ESRCH.
	p := r.k.spawn(2002, 2, "/usr/sbin/useradd", "useradd\x00")
	r.k.beforeSignal = func() { r.k.die(p) }
	res := r.run(r.action(p, 1, killrule.Subject{Image: sp("useradd")}))
	r.k.beforeSignal = nil
	if res.Outcome != event.OutcomeAlreadyExited || res.SignalAttemptedAt == nil {
		t.Errorf("%+v", res)
	}
	if r.k.closed != r.k.opened {
		t.Errorf("handles leaked: opened %d closed %d", r.k.opened, r.k.closed)
	}
	// An exit already observed in the event stream is the same outcome without touching the kernel.
	q := r.k.spawn(2003, 3, "/usr/sbin/useradd", "useradd\x00")
	a := r.action(q, 1, killrule.Subject{Image: sp("useradd")})
	a.Live.Alive.Store(false)
	opened := r.k.opened
	if res := r.run(a); res.Outcome != event.OutcomeAlreadyExited || r.k.opened != opened {
		t.Errorf("%+v opened %d", res, r.k.opened-opened)
	}
}

func TestPIDChangedBetweenDetectionAndOpeningTheHandle(t *testing.T) {
	r := newRig(t, false, []string{"image"}, nil, []string{`^useradd$`})
	old := r.k.spawn(2100, 100, "/usr/sbin/useradd", "useradd\x00")
	a := r.action(old, 1, killrule.Subject{Image: sp("useradd")})
	// The target dies and an innocent process gets its pid before the handle is opened.
	r.k.die(old)
	innocent := r.k.spawn(2100, 999, "/usr/sbin/useradd", "useradd\x00") // even the same program: the start time decides
	res := r.run(a)
	if res.Outcome != event.OutcomeSkipped || *res.Reason != event.SkipIdentityMismatch {
		t.Fatalf("%+v", res)
	}
	if len(innocent.signaled) != 0 || !innocent.alive {
		t.Fatalf("the replacement process was signalled: %v", innocent.signaled)
	}
	if r.k.opened != r.k.closed {
		t.Errorf("handle leaked")
	}
}

func TestTargetEndsAfterTheIdentityCheckAndThePIDIsReused(t *testing.T) {
	r := newRig(t, false, []string{"image"}, nil, []string{`^useradd$`})
	target := r.k.spawn(2200, 100, "/usr/sbin/useradd", "useradd\x00")
	var replacement *fproc
	r.k.beforeSignal = func() { // after the checks, right before the signal
		r.k.die(target)
		replacement = r.k.spawn(2200, 555, "/usr/sbin/useradd", "useradd\x00")
	}
	res := r.run(r.action(target, 1, killrule.Subject{Image: sp("useradd")}))
	if res.Outcome != event.OutcomeAlreadyExited {
		t.Fatalf("%+v", res)
	}
	if len(replacement.signaled) != 0 || !replacement.alive {
		t.Fatalf("the handle must never reach the replacement: %v", replacement.signaled)
	}
}

func TestIdentityNotProvableIsSkipped(t *testing.T) {
	r := newRig(t, false, []string{"image"}, nil, []string{`^useradd$`})
	p := r.k.spawn(2300, 100, "/usr/sbin/useradd", "useradd\x00")
	// The table has no entry for a living process (e.g. started before the table existed).
	r.k.mu.Lock()
	delete(r.k.byPID, 2300)
	r.k.mu.Unlock()
	// The kernel still finds the process by pid for the handle, the table does not know it.
	failing := &failingIdentity{inner: r.k, err: fmt.Errorf("tgid beyond live table")}
	r.w.o.Identity = failing
	r.k.mu.Lock()
	r.k.byPID[2300] = p
	r.k.mu.Unlock()
	res := r.run(r.action(p, 1, killrule.Subject{Image: sp("useradd")}))
	if res.Outcome != event.OutcomeSkipped || *res.Reason != event.SkipIdentityUnverified || res.Error == nil || res.Error.Op != "identity" {
		t.Fatalf("%+v", res)
	}
	if len(p.signaled) != 0 {
		t.Error("no signal without a proven identity")
	}
}

type failingIdentity struct {
	inner Identity
	err   error
}

func (f *failingIdentity) LiveStart(uint32) (uint64, error) { return 0, f.err }

func TestChangedProgramOrArgumentsAreNotKilled(t *testing.T) {
	// The process exec'ed another program after the decision.
	r := newRig(t, false, []string{"image"}, nil, []string{`^useradd$`})
	p := r.k.spawn(2400, 100, "/usr/bin/curl", "curl\x00")
	res := r.run(r.action(p, 1, killrule.Subject{Image: sp("useradd")}))
	if res.Outcome != event.OutcomeSkipped || *res.Reason != event.SkipMatchNoLongerVerif || len(p.signaled) != 0 {
		t.Fatalf("exe changed: %+v", res)
	}
	// A newer exec was already observed in the event stream (exec_index moved on).
	q := r.k.spawn(2401, 101, "/usr/sbin/useradd", "useradd\x00")
	a := r.action(q, 1, killrule.Subject{Image: sp("useradd")})
	a.Live.ExecIndex.Store(2)
	if res := r.run(a); *res.Reason != event.SkipMatchNoLongerVerif || len(q.signaled) != 0 {
		t.Fatalf("newer exec: %+v", res)
	}
	// Arguments: the hit was on argv[2].
	ra := newRig(t, false, []string{"argv"}, []string{"useradd"}, nil)
	s := ra.k.spawn(2402, 102, "/usr/bin/dash", "sh\x00-c\x00useradd bob\x00")
	hit := ra.action(s, 1, killrule.Subject{Argv: []string{"sh", "-c", "useradd bob"}})
	s.cmdline = []byte("sh\x00-c\x00true\x00") // rewritten
	if res := ra.run(hit); *res.Reason != event.SkipMatchNoLongerVerif || len(s.signaled) != 0 {
		t.Fatalf("argv rewritten: %+v", res)
	}
	// Still the same: killed.
	u := ra.k.spawn(2403, 103, "/usr/bin/dash", "sh\x00-c\x00useradd bob\x00")
	if res := ra.run(ra.action(u, 1, killrule.Subject{Argv: []string{"sh", "-c", "useradd bob"}})); res.Outcome != event.OutcomeSignalSent {
		t.Fatalf("argv unchanged: %+v", res)
	}
}

func TestCurrentValuesThatCannotBeReadProveNothing(t *testing.T) {
	r := newRig(t, false, []string{"image"}, nil, []string{`^useradd$`})
	p := r.k.spawn(2500, 100, "/usr/sbin/useradd", "useradd\x00")
	r.k.exeErr = syscall.EACCES
	res := r.run(r.action(p, 1, killrule.Subject{Image: sp("useradd")}))
	if res.Outcome != event.OutcomeSkipped || *res.Reason != event.SkipMatchNoLongerVerif || len(p.signaled) != 0 {
		t.Fatalf("unreadable exe: %+v", res)
	}
	// A vanished /proc entry is the process having gone.
	r.k.exeErr = syscall.ENOENT
	if res := r.run(r.action(p, 1, killrule.Subject{Image: sp("useradd")})); res.Outcome != event.OutcomeAlreadyExited {
		t.Fatalf("%+v", res)
	}
}

func TestDeletedExecutableKeepsAPathMatchProvable(t *testing.T) {
	r := newRig(t, false, []string{"image_path"}, nil, []string{`^/tmp/x/payload$`})
	p := r.k.spawn(2600, 100, "/tmp/x/payload (deleted)", "payload\x00")
	a := r.action(p, 1, killrule.Subject{ImagePath: sp("/tmp/x/payload")})
	a.Process.ImageDeleted = new(bool)
	*a.Process.ImageDeleted = true
	if res := r.run(a); res.Outcome != event.OutcomeSignalSent {
		t.Fatalf("deleted binary recorded as deleted: %+v", res)
	}
	// The record says "not deleted" but /proc says deleted: ambiguous, so unproven.
	q := r.k.spawn(2601, 101, "/tmp/x/payload (deleted)", "payload\x00")
	if res := r.run(r.action(q, 1, killrule.Subject{ImagePath: sp("/tmp/x/payload")})); res.Outcome != event.OutcomeSkipped {
		t.Fatalf("ambiguous path must not be killed on: %+v", res)
	}
}

func TestErrorsAreReportedSeparatelyAndNeverRepeated(t *testing.T) {
	r := newRig(t, false, []string{"image"}, nil, []string{`^useradd$`})
	subj := killrule.Subject{Image: sp("useradd")}

	denied := r.k.spawn(2700, 1, "/usr/sbin/useradd", "useradd\x00")
	r.k.sigErr = syscall.EPERM
	if res := r.run(r.action(denied, 1, subj)); res.Outcome != event.OutcomePermissionDenied || res.Error.Errno != "EPERM" || res.Error.Op != "pidfd_send_signal" {
		t.Fatalf("%+v", res)
	}
	r.k.sigErr = nil

	// File descriptor limit: a resource error, reported as such.
	fdless := r.k.spawn(2701, 2, "/usr/sbin/useradd", "useradd\x00")
	r.k.openErr = syscall.EMFILE
	res := r.run(r.action(fdless, 1, subj))
	r.k.openErr = nil
	if res.Outcome != event.OutcomeError || res.Error.Errno != "EMFILE" || res.Error.Code != int(syscall.EMFILE) || len(fdless.signaled) != 0 {
		t.Fatalf("%+v", res)
	}

	// The worker keeps going afterwards and tried each action exactly once.
	ok := r.k.spawn(2702, 3, "/usr/sbin/useradd", "useradd\x00")
	if res := r.run(r.action(ok, 1, subj)); res.Outcome != event.OutcomeSignalSent {
		t.Fatalf("%+v", res)
	}
	if len(denied.signaled) != 0 || len(fdless.signaled) != 0 {
		t.Errorf("failed attempts must not be repeated")
	}
	c := r.w.Counters()
	if c.PermissionDenied != 1 || c.Errors != 1 || c.SignalsAccepted != 1 || c.SignalAttempts != 2 {
		t.Errorf("counters %+v", c)
	}
}

func TestDryRunNeverTouchesTheKernel(t *testing.T) {
	r := newRig(t, true, []string{"image"}, nil, []string{`^useradd$`})
	p := r.k.spawn(2800, 1, "/usr/sbin/useradd", "useradd\x00")
	a := r.action(p, 1, killrule.Subject{Image: sp("useradd")})
	a.DryRun = true
	r.w.Submit(a)
	res := r.rec.results()
	if len(res) != 1 || res[0].Outcome != event.OutcomeDryRun || !res[0].DryRun || res[0].SignalAttemptedAt != nil {
		t.Fatalf("%+v", res)
	}
	if r.k.opened != 0 || len(p.signaled) != 0 || !p.alive {
		t.Error("dry run opened handles or signalled")
	}
	if c := r.w.Counters(); c.DryRun != 1 || c.SignalAttempts != 0 {
		t.Errorf("%+v", c)
	}
}

func TestBoundedQueueAndShutdown(t *testing.T) {
	r := newRig(t, false, []string{"image"}, nil, []string{`^useradd$`})
	// The worker is not started: nothing drains the queue.
	p := r.k.spawn(2900, 1, "/usr/sbin/useradd", "useradd\x00")
	subj := killrule.Subject{Image: sp("useradd")}
	for i := 0; i < QueueCap+10; i++ {
		r.w.Submit(r.action(p, 1, subj))
	}
	res := r.rec.results()
	if len(res) != 10 {
		t.Fatalf("%d results for 10 actions beyond the bound", len(res))
	}
	for _, d := range res {
		if d.Outcome != event.OutcomeSkipped || *d.Reason != event.SkipActionQueueFull {
			t.Fatalf("%+v", d)
		}
	}
	if c := r.w.Counters(); c.QueueLen != QueueCap || c.Skipped[event.SkipActionQueueFull] != 10 {
		t.Errorf("%+v", c)
	}
	if r.k.opened != 0 {
		t.Error("nothing may be executed while the queue is not served")
	}

	// Shutdown completes the waiting actions as skipped and starts nothing.
	r.w.Start()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.w.Stop(ctx)
	if n := len(r.rec.results()); n != 10+QueueCap {
		t.Fatalf("%d results after shutdown, want %d", n, 10+QueueCap)
	}
	if r.k.opened != 0 || len(p.signaled) != 0 {
		t.Errorf("shutdown must not execute waiting actions (opened %d)", r.k.opened)
	}
	if c := r.w.Counters(); c.Skipped[event.SkipShutdown] != QueueCap {
		t.Errorf("%+v", c.Skipped)
	}
	// Late submissions are skipped as well.
	r.w.Submit(r.action(p, 1, subj))
	last := r.rec.results()[len(r.rec.results())-1]
	if *last.Reason != event.SkipShutdown {
		t.Errorf("%+v", last)
	}
}

func TestSignalLoopsDoNotExist(t *testing.T) {
	// One action, one attempt, even when it fails and the queue is served by the real goroutine.
	r := newRig(t, false, []string{"image"}, nil, []string{`^useradd$`})
	p := r.k.spawn(3000, 1, "/usr/sbin/useradd", "useradd\x00")
	r.k.sigErr = syscall.EAGAIN
	r.w.Start()
	r.w.Submit(r.action(p, 1, killrule.Subject{Image: sp("useradd")}))
	deadline := time.Now().Add(5 * time.Second)
	for len(r.rec.results()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.w.Stop(ctx)
	if res := r.rec.results(); len(res) != 1 || res[0].Outcome != event.OutcomeError {
		t.Fatalf("%+v", res)
	}
	if c := r.w.Counters(); c.SignalAttempts != 1 {
		t.Errorf("attempts %d", c.SignalAttempts)
	}
}

func TestAuditWriteFailureStopsFurtherActions(t *testing.T) {
	r := newRig(t, false, []string{"image"}, nil, []string{`^useradd$`})
	r.rec.err = fmt.Errorf("disk full")
	p := r.k.spawn(3100, 1, "/usr/sbin/useradd", "useradd\x00")
	q := r.k.spawn(3101, 2, "/usr/sbin/useradd", "useradd\x00")
	subj := killrule.Subject{Image: sp("useradd")}
	r.w.Start()
	r.w.Submit(r.action(p, 1, subj))
	select {
	case err := <-r.fat:
		if err == nil {
			t.Fatal("nil fatal error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the fatal callback was not called")
	}
	r.w.Submit(r.action(q, 1, subj))
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.w.Stop(ctx)
	if len(q.signaled) != 0 {
		t.Error("no action may start after a local write error")
	}
}

func TestSkipWithoutRequestedEvent(t *testing.T) {
	r := newRig(t, false, []string{"image"}, nil, []string{`^useradd$`})
	p := r.k.spawn(3200, 1, "/usr/sbin/useradd", "useradd\x00")
	r.w.Skip(r.action(p, 0, killrule.Subject{Image: sp("useradd")}), event.SkipLineageUnconfirmed)
	res := r.rec.results()
	if len(res) != 1 || *res[0].Reason != event.SkipLineageUnconfirmed || r.k.opened != 0 {
		t.Fatalf("%+v", res)
	}
}
