package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Neo23x0/process-watcher/internal/clock"
	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/collector/replay"
	"github.com/Neo23x0/process-watcher/internal/config"
	"github.com/Neo23x0/process-watcher/internal/output"
	"github.com/Neo23x0/process-watcher/internal/schemacheck"
)

const testBoot = "b53c175a-2d90-4d0c-8c94-dfc2c15eb199"

func init() {
	statsInterval = 50 * time.Millisecond
	lossReconcileGap = 100 * time.Millisecond
	readDeadline = 10 * time.Millisecond
}

type rig struct {
	t       *testing.T
	col     *replay.Collector
	logPath string
	cfg     config.Config
	opt     Options
	stderr  *syncBuffer
	cancel  context.CancelFunc
	done    chan int
	code    int
	stopped bool
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func key(tgid uint32, start uint64) collector.Key { return collector.Key{TGID: tgid, StartNS: start} }

var (
	master = key(1200, 8_000_000_000_000)
	worker = key(1201, 8_000_100_000_000)
	shell  = key(1235, 9_000_000_000_000)
)

func snapProc(k, parent collector.Key, visit uint64, image, path string) collector.SnapProc {
	return collector.SnapProc{Key: k, Parent: parent, VisitNS: visit, UID: 33, EUID: 33, GID: 33, Threads: 1,
		Comm: image, Image: image, ImageOK: true, Path: collector.Path{Value: path, Known: true}}
}

func forkEv(parent, child collector.Key, bootNS uint64) collector.Event {
	return collector.Event{Kind: collector.KindFork, BootNS: bootNS, Proc: child, Parent: parent, TID: parent.TGID, UID: 33, EUID: 33, GID: 33, Comm: "forked"}
}

func execEv(proc, parent collector.Key, bootNS uint64, image, path string, argv ...string) collector.Event {
	return collector.Event{Kind: collector.KindExec, BootNS: bootNS, Proc: proc, Parent: parent, TID: proc.TGID, UID: 33, EUID: 33, GID: 33, Comm: image,
		Exec: collector.ExecInfo{Image: image, ImageOK: true, Path: collector.Path{Value: path, Known: true}, Filename: path, FilenameOK: true,
			Args: collector.Args{State: collector.ArgsCaptured, List: argv, Argc: len(argv)}}}
}

func exitEv(proc collector.Key, bootNS uint64, status int32) collector.Event {
	return collector.Event{Kind: collector.KindExit, BootNS: bootNS, Proc: proc, TID: proc.TGID, ExitStatus: status}
}

// newRig prepares an agent run on the replay collector; start() runs it.
func newRig(t *testing.T, snap *collector.Snapshot, mutate ...func(*config.Config)) *rig {
	t.Helper()
	r := &rig{t: t, stderr: &syncBuffer{}, done: make(chan int, 1)}
	r.logPath = filepath.Join(t.TempDir(), "events.jsonl")
	r.cfg = config.Default()
	r.cfg.Watch.ImageContains = []string{"nginx"}
	r.cfg.Outputs.File.Path = r.logPath
	r.cfg.Runtime.HealthInterval = time.Hour
	r.cfg.Runtime.ReconcileInterval = time.Hour
	r.cfg.Runtime.ShutdownTimeout = 2 * time.Second
	for _, m := range mutate {
		m(&r.cfg)
	}
	if snap == nil {
		snap = &collector.Snapshot{StartNS: 1_000_000, EndNS: 2_000_000}
	}
	r.col = replay.New(collector.Info{Kernel: "6.12.0-test", Arch: "arm64", RingBytes: 1 << 24, HooksActiveNS: 500_000}, snap)
	fake := &clock.Fake{Boot: 10_000_000_000_000, Wall: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	r.opt = Options{
		Version: "test",
		Stderr:  r.stderr,
		OpenCollector: func(o collector.Options) (collector.Collector, error) {
			r.col.SetOptions(o)
			return r.col, nil
		},
		Preflight:  func() error { return nil },
		BootID:     func() (string, error) { return testBoot, nil },
		Hostname:   func() (string, error) { return "web01", nil },
		Clock:      fake,
		CheckPidfd: func() error { return nil },
		SnapshotArgs: func(k collector.Key, _ collector.ArgLimits) collector.Args {
			return collector.Args{State: collector.ArgsFailed}
		},
	}
	return r
}

func (r *rig) start() {
	r.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() { r.done <- Run(ctx, &config.Resolved{Command: config.CommandRun, Config: r.cfg}, r.opt) }()
	r.t.Cleanup(func() { r.stop() })
}

// stop cancels the run and returns the exit code.
func (r *rig) stop() int {
	if r.stopped {
		return r.code
	}
	r.stopped = true
	r.cancel()
	select {
	case r.code = <-r.done:
	case <-time.After(15 * time.Second):
		r.t.Fatalf("agent did not stop; stderr:\n%s", r.stderr.String())
	}
	return r.code
}

type line struct {
	raw []byte
	m   map[string]any
}

func (l line) typ() string { s, _ := l.m["event_type"].(string); return s }
func (l line) pid() int {
	p, _ := l.m["process"].(map[string]any)
	f, _ := p["pid"].(float64)
	return int(f)
}
func (l line) get(path string) any {
	var cur any = l.m
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

func (r *rig) lines() []line {
	b, _ := os.ReadFile(r.logPath)
	var out []line
	for _, raw := range bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n")) {
		if len(raw) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			r.t.Fatalf("log line is not JSON: %v\n%s", err, raw)
		}
		out = append(out, line{raw, m})
	}
	return out
}

func (r *rig) wait(what string, cond func([]line) bool) []line {
	r.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ls := r.lines()
		if cond(ls) {
			return ls
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("timeout waiting for %s; events: %s\nstderr:\n%s", what, types(ls), r.stderr.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func types(ls []line) string {
	var t []string
	for _, l := range ls {
		s := l.typ()
		if l.pid() != 0 {
			s += fmt.Sprintf(":%d", l.pid())
		}
		t = append(t, s)
	}
	return strings.Join(t, " ")
}

func count(ls []line, typ string) int {
	n := 0
	for _, l := range ls {
		if l.typ() == typ {
			n++
		}
	}
	return n
}

// validateAll checks every line of the log against the schema.
func (r *rig) validateAll() {
	r.t.Helper()
	for _, l := range r.lines() {
		if err := schemacheck.Validate(l.raw); err != nil {
			r.t.Errorf("schema violation in %s: %v\n%s", l.typ(), err, l.raw)
		}
	}
}

func TestStartupSequenceDiscoversThenReady(t *testing.T) {
	snap := &collector.Snapshot{StartNS: 1_000_000, EndNS: 2_000_000, Procs: []collector.SnapProc{
		snapProc(key(1, 1), key(0, 0), 1_100_000, "systemd", "/usr/lib/systemd/systemd"),
		snapProc(master, key(1, 1), 1_200_000, "nginx", "/usr/sbin/nginx"),
		snapProc(worker, master, 1_300_000, "nginx", "/usr/sbin/nginx"),
	}}
	r := newRig(t, snap)
	r.start()
	ls := r.wait("ready", func(ls []line) bool { return count(ls, "agent.ready") == 1 })
	if got := types(ls); got != "agent.started process.discovered:1200 process.discovered:1201 agent.ready" {
		t.Fatalf("startup order: %s", got)
	}
	if ls[0].get("details.complete_capture") != false || ls[0].get("details.phase") != "initializing" {
		t.Errorf("agent.started must not claim completeness: %v", ls[0].m["details"])
	}
	if got := ls[3].get("details.discovered_roots"); got != float64(1) {
		t.Errorf("ready details %v", ls[3].m["details"])
	}

	// Live records after ready: a new child of the worker.
	r.col.Push(forkEv(worker, shell, 20_000_000), execEv(shell, worker, 20_000_100, "dash", "/usr/bin/dash", "sh"), exitEv(shell, 20_000_200, 0))
	ls = r.wait("child lifecycle", func(ls []line) bool { return count(ls, "process.exit") == 1 })
	if got := types(ls[4:]); got != "process.fork:1235 process.exec:1235 process.exit:1235" {
		t.Errorf("live events: %s", got)
	}
	if code := r.stop(); code != ExitOK {
		t.Fatalf("exit code %d\n%s", code, r.stderr.String())
	}
	ls = r.lines()
	if last := ls[len(ls)-1]; last.typ() != "agent.stopped" || last.get("details.reason") != "signal" {
		t.Errorf("last event %s %v", last.typ(), last.get("details.reason"))
	}
	if !r.col.Stopped() {
		t.Error("the capture must be stopped at shutdown")
	}
	prev := 0.0
	for _, l := range ls {
		if seq := l.m["sequence"].(float64); seq != prev+1 {
			t.Errorf("sequence %v after %v", seq, prev)
		} else {
			prev = seq
		}
	}
	r.validateAll()
}

func TestRecordLossBecomesAGapAndAReconciliation(t *testing.T) {
	r := newRig(t, nil)
	var mu sync.Mutex
	st := collector.Stats{}
	r.col.SetStatsFunc(func() collector.Stats { mu.Lock(); defer mu.Unlock(); return st })
	r.start()
	r.wait("ready", func(ls []line) bool { return count(ls, "agent.ready") == 1 })
	r.col.Push(execEv(master, key(1, 1), 20_000_000, "nginx", "/usr/sbin/nginx", "nginx"))
	r.wait("root", func(ls []line) bool { return count(ls, "process.exec") == 1 })

	// The kernel counters show losses; the living processes now include a child the engine never saw.
	r.col.SetSnapshotFunc(func() (*collector.Snapshot, error) {
		return &collector.Snapshot{StartNS: 30_000_000, EndNS: 30_100_000, Procs: []collector.SnapProc{
			snapProc(master, key(1, 1), 30_000_100, "nginx", "/usr/sbin/nginx"),
			snapProc(shell, master, 30_000_200, "dash", "/usr/bin/dash"),
		}}, nil
	})
	mu.Lock()
	st.LostFork, st.LostExec = 3, 2
	mu.Unlock()

	ls := r.wait("gap and discovery", func(ls []line) bool { return count(ls, "agent.gap") == 1 && count(ls, "process.discovered") == 1 })
	var gap, disc line
	for _, l := range ls {
		switch l.typ() {
		case "agent.gap":
			gap = l
		case "process.discovered":
			disc = l
		}
	}
	if gap.get("details.cause") != "ring_buffer_full" || gap.get("details.lost.fork") != float64(3) || gap.get("details.lost.exec") != float64(2) || gap.get("details.lost_total") != float64(5) {
		t.Errorf("gap %v", gap.m["details"])
	}
	if gap.get("data_quality.collection_gap") != true {
		t.Error("a gap event is marked as a collection gap")
	}
	if disc.pid() != 1235 || disc.get("lineage.complete") != false || disc.get("data_quality.collection_gap") != true || disc.get("details.discovery") != "reconcile" {
		t.Errorf("a process found after a loss has an unconfirmed lineage: %v %v", disc.m["lineage"], disc.m["data_quality"])
	}
	// The same loss is reported once.
	time.Sleep(300 * time.Millisecond)
	if n := count(r.lines(), "agent.gap"); n != 1 {
		t.Errorf("%d gap events for one loss", n)
	}
	r.stop()
	r.validateAll()
}

func TestStoppedCarriesTheFinalFilterCounters(t *testing.T) {
	// The exclusion counters of the last interval must not be lost at shutdown:
	// agent.health may be a minute away.
	r := newRig(t, nil, func(c *config.Config) { c.Exclude.ImageContains = []string{"dash"} })
	r.start()
	r.wait("ready", func(ls []line) bool { return count(ls, "agent.ready") == 1 })
	r.col.Push(
		execEv(master, key(1, 1), 20_000_000, "nginx", "/usr/sbin/nginx", "nginx"),
		forkEv(master, shell, 20_000_100),
		execEv(shell, master, 20_000_200, "dash", "/usr/bin/dash", "sh"),
		exitEv(shell, 20_000_300, 0),
	)
	r.wait("the excluded child", func(ls []line) bool { return count(ls, "process.exit") == 1 })
	if code := r.stop(); code != ExitOK {
		t.Fatalf("exit code %d\n%s", code, r.stderr.String())
	}
	ls := r.lines()
	last := ls[len(ls)-1]
	if last.typ() != "agent.stopped" {
		t.Fatalf("last event %s", last.typ())
	}
	// fork (inherited nginx image: not excluded), exec dash and exit (image dash): two excluded events
	if got, _ := last.get("details.filter.excluded_remote").(float64); got < 1 {
		t.Errorf("agent.stopped lacks the final exclusion counters: %v", last.m["details"])
	}
	for _, key := range []string{"excluded_all", "suppressed_by_depth"} {
		if last.get("details.filter."+key) == nil {
			t.Errorf("agent.stopped lacks details.filter.%s", key)
		}
	}
	r.validateAll()
}

func TestHealthReportsCountersOfTheRun(t *testing.T) {
	r := newRig(t, nil, func(c *config.Config) { c.Runtime.HealthInterval = 60 * time.Millisecond })
	r.col.SetStats(collector.Stats{Fork: 7, Exec: 5, Exit: 4, ThreadClones: 9})
	r.start()
	r.col.Push(execEv(master, key(1, 1), 20_000_000, "nginx", "/usr/sbin/nginx"), forkEv(master, shell, 20_000_100))
	ls := r.wait("health with the tree", func(ls []line) bool {
		for _, l := range ls {
			if l.typ() == "agent.health" && l.get("details.tracked.roots") == float64(1) && l.get("details.tracked.instances") == float64(2) {
				return true
			}
		}
		return false
	})
	var h line
	for _, l := range ls {
		if l.typ() == "agent.health" && l.get("details.tracked.instances") == float64(2) {
			h = l
		}
	}
	if h.get("details.collector.records.fork") != float64(7) || h.get("details.collector.thread_clones_skipped") != float64(9) {
		t.Errorf("collector counters %v", h.get("details.collector"))
	}
	events, _ := h.get("details.events").(map[string]any)
	if h.get("details.outputs.file.lines") == nil || events["process.exec"] != float64(1) || h.get("details.response") != nil {
		t.Errorf("health details %v", h.m["details"])
	}
	if h.get("details.tracked.limit") != float64(65536) {
		t.Errorf("limit %v", h.get("details.tracked.limit"))
	}
	r.stop()
	r.validateAll()
}

func TestProcessTableLimitIsReportedAsAGap(t *testing.T) {
	r := newRig(t, nil, func(c *config.Config) { c.Runtime.MaxProcesses = 2 })
	r.start()
	r.col.Push(execEv(master, key(1, 1), 20_000_000, "nginx", "/usr/sbin/nginx"), forkEv(master, worker, 20_000_100), forkEv(master, shell, 20_000_200))
	ls := r.wait("table gap", func(ls []line) bool { return count(ls, "agent.gap") >= 1 })
	for _, l := range ls {
		if l.typ() == "agent.gap" {
			if l.get("details.cause") != "process_table_full" {
				t.Errorf("cause %v", l.get("details.cause"))
			}
			break
		}
	}
	r.stop()
	r.validateAll()
}

func TestRemoteOutputGetsTheSameBytesAndShutdownEndsLocally(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no udp: %v", err)
	}
	defer pc.Close()
	var mu sync.Mutex
	var got [][]byte
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			got = append(got, append([]byte(nil), buf[:n]...))
			mu.Unlock()
		}
	}()
	r := newRig(t, nil, func(c *config.Config) { c.Outputs.UDP.Address = pc.LocalAddr().String() })
	r.start()
	r.col.Push(execEv(master, key(1, 1), 20_000_000, "nginx", "/usr/sbin/nginx"))
	r.wait("exec", func(ls []line) bool { return count(ls, "process.exec") == 1 })
	time.Sleep(200 * time.Millisecond)
	r.stop()

	local := map[string]bool{}
	for _, l := range r.lines() {
		local[string(l.raw)+"\n"] = true
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) < 3 {
		t.Fatalf("udp received %d datagrams", len(got))
	}
	seenTypes := map[string]bool{}
	for _, d := range got {
		if !local[string(d)] {
			t.Errorf("datagram differs from every local line:\n%s", d)
		}
		var m map[string]any
		json.Unmarshal(d, &m)
		seenTypes[m["event_type"].(string)] = true
	}
	if !seenTypes["agent.started"] || !seenTypes["process.exec"] || seenTypes["agent.stopped"] {
		t.Errorf("types at the remote: %v (agent.stopped is stored locally only)", seenTypes)
	}
	ls := r.lines()
	if last := ls[len(ls)-1]; last.typ() != "agent.stopped" || last.get("details.outputs.udp") == nil {
		t.Errorf("last %s outputs %v", last.typ(), last.get("details.outputs"))
	}
	r.validateAll()
}

// failingLog fails every write after n successful ones.
type failingLog struct {
	mu     sync.Mutex
	n      int
	lines  [][]byte
	closed bool
}

func (f *failingLog) Write(b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.lines) >= f.n {
		return errors.New("no space left on device")
	}
	f.lines = append(f.lines, append([]byte(nil), b...))
	return nil
}
func (f *failingLog) Sync() error               { return nil }
func (f *failingLog) Close() error              { f.closed = true; return nil }
func (f *failingLog) Stats() output.FileStats   { return output.FileStats{} }
func (f *failingLog) Repair() output.RepairInfo { return output.RepairInfo{} }

func TestLocalLogFailureEndsTheAgentWithExitCode1(t *testing.T) {
	r := newRig(t, nil)
	fl := &failingLog{n: 3} // started, ready, one more
	r.opt.OpenLog = func(output.FileOptions) (logFile, error) { return fl, nil }
	r.start()
	r.col.Push(execEv(master, key(1, 1), 20_000_000, "nginx", "/usr/sbin/nginx"), forkEv(master, shell, 20_000_100))
	select {
	case code := <-r.done:
		r.code, r.stopped = code, true
		if code != ExitRuntime {
			t.Fatalf("exit code %d, want 1", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the agent must not continue without its mandatory log")
	}
	if !strings.Contains(r.stderr.String(), "no space left on device") {
		t.Errorf("stderr must say what failed:\n%s", r.stderr.String())
	}
	if !fl.closed {
		t.Error("the log must be closed")
	}
}

// syncFailingLog accepts every line and fails the final fsync.
type syncFailingLog struct{ *failingLog }

func (syncFailingLog) Sync() error { return errors.New("input/output error") }

func TestLocalLogFailureAtShutdownIsAFailureOfTheRun(t *testing.T) {
	// A disk that fills up during the shutdown must not end in "success": the
	// mandatory local log is incomplete.
	t.Run("agent.stopped cannot be written", func(t *testing.T) {
		r := newRig(t, nil)
		fl := &failingLog{n: 2} // agent.started and agent.ready; agent.stopped fails
		r.opt.OpenLog = func(output.FileOptions) (logFile, error) { return fl, nil }
		r.start()
		time.Sleep(200 * time.Millisecond)
		if code := r.stop(); code != ExitRuntime {
			t.Fatalf("exit code %d, want %d\n%s", code, ExitRuntime, r.stderr.String())
		}
		if !strings.Contains(r.stderr.String(), "no space left on device") {
			t.Errorf("stderr must say what failed:\n%s", r.stderr.String())
		}
		if !fl.closed {
			t.Error("the log must be closed")
		}
	})
	t.Run("final fsync fails", func(t *testing.T) {
		r := newRig(t, nil)
		fl := &failingLog{n: 1000}
		r.opt.OpenLog = func(output.FileOptions) (logFile, error) { return syncFailingLog{fl}, nil }
		r.start()
		time.Sleep(200 * time.Millisecond)
		if code := r.stop(); code != ExitRuntime {
			t.Fatalf("exit code %d, want %d\n%s", code, ExitRuntime, r.stderr.String())
		}
		if !strings.Contains(r.stderr.String(), "input/output error") {
			t.Errorf("stderr must say what failed:\n%s", r.stderr.String())
		}
	})
}

func TestLossDuringTheStartupWindowIsReported(t *testing.T) {
	// The ring buffer overflowed while the hooks were attached and the startup
	// snapshot was taken: the kernel counters already show losses when the
	// first reconciliation applies the snapshot. That must not be absorbed into
	// a baseline: it is an agent.gap, and the processes discovered by this
	// snapshot cannot vouch for their relations.
	snap := &collector.Snapshot{StartNS: 1_000_000, EndNS: 2_000_000, Procs: []collector.SnapProc{
		snapProc(key(1, 1), key(0, 0), 1_100_000, "systemd", "/usr/lib/systemd/systemd"),
		snapProc(master, key(1, 1), 1_200_000, "nginx", "/usr/sbin/nginx"),
		snapProc(worker, master, 1_300_000, "nginx", "/usr/sbin/nginx"),
	}}
	r := newRig(t, snap)
	r.col.SetStats(collector.Stats{LostFork: 4, LostExec: 1})
	r.start()
	ls := r.wait("ready", func(ls []line) bool { return count(ls, "agent.ready") == 1 })
	if got := types(ls); got != "agent.started agent.gap process.discovered:1200 process.discovered:1201 agent.ready" {
		t.Fatalf("startup order: %s", got)
	}
	gap := ls[1]
	if gap.get("details.cause") != "ring_buffer_full" || gap.get("details.lost.fork") != float64(4) || gap.get("details.lost.exec") != float64(1) || gap.get("details.lost_total") != float64(5) {
		t.Errorf("gap %v", gap.m["details"])
	}
	for _, d := range ls[2:4] {
		if d.get("lineage.complete") != false || d.get("data_quality.collection_gap") != true {
			t.Errorf("pid %d discovered after a loss must have an unconfirmed lineage: %v %v", d.pid(), d.m["lineage"], d.m["data_quality"])
		}
	}
	// The same loss is reported once, and later discoveries are confirmed again.
	time.Sleep(300 * time.Millisecond)
	if n := count(r.lines(), "agent.gap"); n != 1 {
		t.Errorf("%d gap events for one loss", n)
	}
	r.stop()
	r.validateAll()
}

func TestUnreadableKernelCountersEndTheAgent(t *testing.T) {
	t.Run("persistent failure", func(t *testing.T) {
		r := newRig(t, nil)
		r.start()
		r.wait("ready", func(ls []line) bool { return count(ls, "agent.ready") == 1 })
		r.col.SetStatsError(errors.New("map lookup failed"))
		select {
		case code := <-r.done:
			r.code, r.stopped = code, true
			if code != ExitRuntime {
				t.Fatalf("exit code %d, want %d", code, ExitRuntime)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("an agent that cannot see record loss must not carry on")
		}
		if !strings.Contains(r.stderr.String(), "loss counters") {
			t.Errorf("stderr must say what failed:\n%s", r.stderr.String())
		}
		ls := r.lines()
		if last := ls[len(ls)-1]; last.typ() != "agent.stopped" || last.get("details.reason") != "fatal_error" {
			t.Errorf("last event %s %v", last.typ(), last.get("details.reason"))
		}
	})
	t.Run("transient failure", func(t *testing.T) {
		r := newRig(t, nil)
		r.start()
		r.wait("ready", func(ls []line) bool { return count(ls, "agent.ready") == 1 })
		r.col.SetStatsError(errors.New("map lookup failed"))
		time.Sleep(3 * statsInterval)
		r.col.SetStatsError(nil)
		time.Sleep(10 * statsInterval) // well beyond the allowed number of failures
		select {
		case code := <-r.done:
			t.Fatalf("a few failed reads must not end the agent (exit %d)\n%s", code, r.stderr.String())
		default:
		}
		if code := r.stop(); code != ExitOK {
			t.Fatalf("exit code %d\n%s", code, r.stderr.String())
		}
	})
}

func TestPrerequisitesAreCheckedBeforeAnySideEffect(t *testing.T) {
	r := newRig(t, nil)
	r.opt.Preflight = func() error {
		return &collector.PrerequisiteError{Check: "privileges", Detail: "needs root"}
	}
	r.start()
	if code := r.stop(); code != ExitPlatform {
		t.Fatalf("exit code %d, want 3", code)
	}
	if _, err := os.Stat(r.logPath); err == nil {
		t.Error("the log was created although the prerequisites are not met")
	}
	if !strings.Contains(r.stderr.String(), "needs root") {
		t.Errorf("stderr: %s", r.stderr.String())
	}

	// The collector failing to start is exit 3 as well when it names a prerequisite.
	r2 := newRig(t, nil)
	r2.opt.OpenCollector = func(collector.Options) (collector.Collector, error) {
		return nil, &collector.PrerequisiteError{Check: "kernel BTF", Detail: "no BTF"}
	}
	r2.start()
	if code := r2.stop(); code != ExitPlatform {
		t.Fatalf("exit code %d, want 3", code)
	}
}

func TestMissingWebhookTokenIsAConfigurationError(t *testing.T) {
	r := newRig(t, nil, func(c *config.Config) {
		c.Outputs.Webhook.URL = "https://example.org/hook"
		c.Outputs.Webhook.TokenEnv = "PW_TEST_TOKEN"
	})
	r.opt.Getenv = func(string) string { return "" }
	r.start()
	if code := r.stop(); code != ExitConfig {
		t.Fatalf("exit code %d, want 2\n%s", code, r.stderr.String())
	}
	if _, err := os.Stat(r.logPath); err == nil {
		t.Error("nothing may be created for a configuration error")
	}
}

func TestStartupReconciliationFailureIsFatalButStillStoredAsStopped(t *testing.T) {
	r := newRig(t, nil)
	r.col.SetSnapshotFunc(func() (*collector.Snapshot, error) { return nil, errors.New("iterator failed") })
	r.start()
	if code := r.stop(); code != ExitRuntime {
		t.Fatalf("exit code %d\n%s", code, r.stderr.String())
	}
	ls := r.lines()
	if len(ls) != 2 || ls[0].typ() != "agent.started" || ls[1].typ() != "agent.stopped" || ls[1].get("details.reason") != "fatal_error" {
		t.Fatalf("events %s", types(ls))
	}
	if !strings.Contains(fmt.Sprint(ls[1].get("details.error")), "iterator failed") {
		t.Errorf("error %v", ls[1].get("details.error"))
	}
	r.validateAll()
}

// ---------------------------------------------------------------------------
// kill wiring

type fakeSys struct {
	mu      sync.Mutex
	exe     map[int]string
	cmdline map[int]string
	signals []string
	nextFD  int
	open    int
}

func (f *fakeSys) PidfdOpen(tgid int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.exe[tgid]; !ok {
		return -1, syscall.ESRCH
	}
	f.nextFD++
	f.open++
	return f.nextFD, nil
}
func (f *fakeSys) PidfdSignal(fd int, sig syscall.Signal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sig != 0 {
		f.signals = append(f.signals, fmt.Sprintf("fd%d:%d", fd, int(sig)))
	}
	return nil
}
func (f *fakeSys) Close(int) error { f.mu.Lock(); f.open--; f.mu.Unlock(); return nil }
func (f *fakeSys) ExeLink(tgid int) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.exe[tgid]; ok {
		return e, nil
	}
	return "", syscall.ENOENT
}
func (f *fakeSys) Cmdline(tgid int, max int) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return []byte(f.cmdline[tgid]), false, nil
}
func (f *fakeSys) sigs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.signals...)
}

func (f *fakeSys) openCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.open
}

func (f *fakeSys) BootNS() uint64 { return 10_000_000_999_999 }
func (f *fakeSys) Now() time.Time { return time.Date(2026, 10, 17, 12, 0, 1, 0, time.UTC) }

func killRig(t *testing.T, dry bool) (*rig, *fakeSys) {
	sys := &fakeSys{exe: map[int]string{int(shell.TGID): "/usr/sbin/useradd"}, cmdline: map[int]string{int(shell.TGID): "useradd\x00bob\x00"}}
	r := newRig(t, nil, func(c *config.Config) {
		c.Capture.Argv = true
		c.Kill = config.KillConfig{Enabled: true, DryRun: dry, Fields: []string{"image", "argv"}, Strings: []string{}, Regex: []string{`^(useradd|usermod)$`}}
	})
	r.opt.System = sys
	return r, sys
}

func TestKillIsWiredThroughTheWorker(t *testing.T) {
	r, sys := killRig(t, false)
	r.col.SetLiveStart(shell.TGID, shell.StartNS) // the live table of the collector
	r.start()
	r.wait("ready", func(ls []line) bool { return count(ls, "agent.ready") == 1 })
	if !r.col.Options().LiveTable {
		t.Error("the live table must be enabled for the kill feature")
	}
	r.col.Push(execEv(master, key(1, 1), 20_000_000, "nginx", "/usr/sbin/nginx", "nginx"),
		forkEv(master, shell, 20_000_100),
		execEv(shell, master, 20_000_200, "useradd", "/usr/sbin/useradd", "useradd", "bob"))
	ls := r.wait("kill pair", func(ls []line) bool { return count(ls, "response.kill_result") == 1 })

	var req, res line
	for _, l := range ls {
		switch l.typ() {
		case "response.kill_requested":
			req = l
		case "response.kill_result":
			res = l
		}
	}
	if req.raw == nil || res.get("details.outcome") != "signal_sent" || req.get("details.outcome") != "pending" {
		t.Fatalf("events: %s", types(ls))
	}
	if req.get("details.action_id") != res.get("details.action_id") || res.get("source") != "agent" {
		t.Errorf("request and result must share the action id: %v %v", req.get("details.action_id"), res.get("details.action_id"))
	}
	if sigs := sys.sigs(); len(sigs) != 1 || !strings.HasSuffix(sigs[0], ":9") {
		t.Errorf("signals %v", sigs)
	}
	if n := sys.openCount(); n != 0 {
		t.Errorf("%d pidfds left open", n)
	}
	// The decision was written before the result.
	if req.m["sequence"].(float64) >= res.m["sequence"].(float64) {
		t.Error("decision must precede the result")
	}
	r.col.Push(exitEv(shell, 20_001_000, 9))
	ls = r.wait("exit", func(ls []line) bool { return count(ls, "process.exit") == 1 })
	exit := ls[len(ls)-1]
	if exit.get("details.response_action_id") != req.get("details.action_id") || exit.get("details.signal") != float64(9) {
		t.Errorf("exit correlation %v", exit.m["details"])
	}
	// Health reports the response counters.
	r.stop()
	ls = r.lines()
	stopped := ls[len(ls)-1]
	if stopped.get("details.response.signal_attempts") != float64(1) || stopped.get("details.response.signals_accepted") != float64(1) || stopped.get("details.response.rule_hits") != float64(1) {
		t.Errorf("response stats %v", stopped.get("details.response"))
	}
	r.validateAll()
}

func TestDryRunWritesTheAuditButSendsNothing(t *testing.T) {
	r, sys := killRig(t, true)
	r.col.SetLiveStart(shell.TGID, shell.StartNS)
	r.start()
	r.col.Push(execEv(master, key(1, 1), 20_000_000, "nginx", "/usr/sbin/nginx", "nginx"),
		forkEv(master, shell, 20_000_100),
		execEv(shell, master, 20_000_200, "useradd", "/usr/sbin/useradd", "useradd"))
	ls := r.wait("kill pair", func(ls []line) bool { return count(ls, "response.kill_result") == 1 })
	for _, l := range ls {
		if l.typ() == "response.kill_result" && (l.get("details.outcome") != "dry_run" || l.get("details.dry_run") != true || l.get("details.signal_attempted_at") != nil) {
			t.Errorf("result %v", l.m["details"])
		}
	}
	if len(sys.sigs()) != 0 || sys.openCount() != 0 {
		t.Errorf("dry run touched the kernel: signals %v open %d", sys.sigs(), sys.openCount())
	}
	r.stop()
	r.validateAll()
}

func TestKillNeedsWorkingPidfdOrRefusesToStart(t *testing.T) {
	r, _ := killRig(t, false)
	r.opt.CheckPidfd = func() error { return errors.New("pidfd_open: function not implemented") }
	r.start()
	if code := r.stop(); code != ExitPlatform {
		t.Fatalf("exit code %d, want 3\n%s", code, r.stderr.String())
	}
	if _, err := os.Stat(r.logPath); err == nil {
		t.Error("a refused start must not create the log")
	}
	if !strings.Contains(r.stderr.String(), "pidfd") {
		t.Errorf("the diagnosis must name pidfd:\n%s", r.stderr.String())
	}
}

func TestLivingChildrenOfARootThatAppearedAtRuntimeAreDiscovered(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	r.wait("ready", func(ls []line) bool { return count(ls, "agent.ready") == 1 })
	// A process that already had a child execs into nginx: the child's fork record was never
	// associated with a tree, only a snapshot can find it.
	r.col.SetSnapshotFunc(func() (*collector.Snapshot, error) {
		return &collector.Snapshot{StartNS: 30_000_000, EndNS: 30_100_000, Procs: []collector.SnapProc{
			snapProc(master, key(1, 1), 30_000_100, "nginx", "/usr/sbin/nginx"),
			snapProc(worker, master, 30_000_200, "sleep", "/usr/bin/sleep"),
		}}, nil
	})
	r.col.Push(execEv(master, key(1, 1), 20_000_000, "nginx", "/usr/sbin/nginx", "nginx"))
	ls := r.wait("the pre-existing child", func(ls []line) bool { return count(ls, "process.discovered") == 1 })
	for _, l := range ls {
		if l.typ() != "process.discovered" {
			continue
		}
		if l.pid() != 1201 || l.get("lineage.role") != "descendant" || l.get("root.pid") != float64(1200) || l.get("details.discovery") != "reconcile" {
			t.Errorf("discovered %v %v", l.m["lineage"], l.m["details"])
		}
		if l.get("lineage.complete") != true {
			t.Errorf("no loss happened, the relation from the snapshot is complete: %v", l.m["lineage"])
		}
	}
	r.stop()
	r.validateAll()
}
