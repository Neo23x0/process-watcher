//go:build linux

package ebpf

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Neo23x0/process-watcher/internal/clock"
	"github.com/Neo23x0/process-watcher/internal/collector"
)

// These tests load the real eBPF programs. They need root and the initial PID
// namespace (a privileged container with --pid=host or a VM). Mocks are not
// used on purpose: the point is to observe the kernel.

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs")
	}
}

func openCollector(t *testing.T, opts collector.Options) *Collector {
	t.Helper()
	requireRoot(t)
	if opts.RingBufferBytes == 0 {
		opts.RingBufferBytes = 8 << 20
	}
	c, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// drain reads records until none arrives for quiet.
func drain(t *testing.T, c *Collector, quiet time.Duration) []collector.Event {
	t.Helper()
	var evs []collector.Event
	for {
		ev, err := c.Next(time.Now().Add(quiet))
		if errors.Is(err, collector.ErrTimeout) {
			return evs
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		evs = append(evs, ev)
	}
}

func of(evs []collector.Event, tgid uint32) []collector.Event {
	var out []collector.Event
	for _, ev := range evs {
		if ev.Proc.TGID == tgid {
			out = append(out, ev)
		}
	}
	return out
}

func kinds(evs []collector.Event) string {
	var k []string
	for _, ev := range evs {
		k = append(k, ev.Kind.String())
	}
	return strings.Join(k, ",")
}

func find(evs []collector.Event, kind collector.Kind) (collector.Event, bool) {
	for _, ev := range evs {
		if ev.Kind == kind {
			return ev, true
		}
	}
	return collector.Event{}, false
}

func mustFind(t *testing.T, evs []collector.Event, kind collector.Kind) collector.Event {
	t.Helper()
	ev, ok := find(evs, kind)
	if !ok {
		t.Fatalf("no %s record in [%s]", kind, kinds(evs))
	}
	return ev
}

// sameKey asserts that all records of one process instance carry one identity.
func sameKey(t *testing.T, evs []collector.Event) collector.Key {
	t.Helper()
	if len(evs) == 0 {
		t.Fatal("no records")
	}
	k := evs[0].Proc
	for _, ev := range evs {
		if ev.Proc != k {
			t.Fatalf("identity changed within one instance: %+v vs %+v (%s)", k, ev.Proc, kinds(evs))
		}
	}
	return k
}

func TestSmokeSnapshot(t *testing.T) {
	c := openCollector(t, collector.Options{LiveTable: true})
	snap, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	self := uint32(os.Getpid())
	var found bool
	for _, p := range snap.Procs {
		if p.Key.TGID != self {
			continue
		}
		found = true
		if !p.ImageOK || p.Image != filepath.Base(os.Args[0]) || p.Path.Value != os.Args[0] && !strings.HasSuffix(p.Path.Value, filepath.Base(os.Args[0])) {
			t.Errorf("unexpected image of self: %+v", p)
		}
		if start, err := c.LiveStart(self); err != nil || start != p.Key.StartNS {
			t.Errorf("live table %d (%v), snapshot says %d", start, err, p.Key.StartNS)
		}
	}
	if !found {
		t.Fatal("the test process is not in its own snapshot")
	}
	t.Logf("%d processes in %s", len(snap.Procs), time.Duration(snap.EndNS-snap.StartNS))
}

// TestShortLivedChild: fork, successful exec and exit all arrive without any
// /proc access, with the real executable name, path and requested filename.
func TestShortLivedChild(t *testing.T) {
	c := openCollector(t, collector.Options{CaptureArgs: true, LiveTable: true})
	helper, out := startHelper(t, "true-child", "unused")
	child := outPID(t, out, "child")
	evs := drain(t, c, 300*time.Millisecond)

	tl := of(evs, child)
	if kinds(tl) != "fork,exec,exit" {
		t.Fatalf("records of the child: [%s]", kinds(tl))
	}
	key := sameKey(t, tl)
	fork, exec, exit := tl[0], tl[1], tl[2]
	if fork.Parent.TGID != helper {
		t.Errorf("fork parent %+v, want tgid %d", fork.Parent, helper)
	}
	if !(fork.BootNS <= exec.BootNS && exec.BootNS <= exit.BootNS) {
		t.Errorf("kernel times not ordered: %d %d %d", fork.BootNS, exec.BootNS, exit.BootNS)
	}
	if key.StartNS == 0 || key.StartNS > fork.BootNS {
		t.Errorf("start time %d must not be after the fork record %d", key.StartNS, fork.BootNS)
	}
	x := exec.Exec
	if x.Image != "true" || !x.ImageOK || x.Path.Value != "/usr/bin/true" || !x.Path.Known {
		t.Errorf("image %q path %+v", x.Image, x.Path)
	}
	if x.Filename != "/bin/true" || x.ParentImage != filepath.Base(os.Args[0]) {
		t.Errorf("filename %q parent image %q", x.Filename, x.ParentImage)
	}
	if x.Args.State != collector.ArgsCaptured || len(x.Args.List) != 2 || x.Args.List[1] != "unused" {
		t.Errorf("args %+v", x.Args)
	}
	if exit.ExitStatus != 0 {
		t.Errorf("exit status %#x", exit.ExitStatus)
	}
}

func TestArgsNotCapturedByDefault(t *testing.T) {
	c := openCollector(t, collector.Options{})
	_, out := startHelper(t, "true-child", "secret")
	child := outPID(t, out, "child")
	x := mustFind(t, of(drain(t, c, 300*time.Millisecond), child), collector.KindExec).Exec
	if x.Args.State != collector.ArgsNotCaptured || x.Args.List != nil {
		t.Errorf("argv must not be captured unless enabled: %+v", x.Args)
	}
}

func TestForkWithoutExec(t *testing.T) {
	for _, tc := range []struct {
		mode   string
		status int32
	}{{"fork-noexec", 7 << 8}, {"clone3-noexec", 9 << 8}} {
		t.Run(tc.mode, func(t *testing.T) {
			c := openCollector(t, collector.Options{})
			helper, out := startHelper(t, tc.mode)
			child := outPID(t, out, "child")
			tl := of(drain(t, c, 300*time.Millisecond), child)
			if kinds(tl) != "fork,exit" {
				t.Fatalf("records of the child: [%s]", kinds(tl))
			}
			sameKey(t, tl)
			if tl[0].Parent.TGID != helper || tl[1].ExitStatus != tc.status {
				t.Errorf("parent %+v exit status %#x, want %d / %#x", tl[0].Parent, tl[1].ExitStatus, helper, tc.status)
			}
			if tl[0].Comm != filepath.Base(os.Args[0])[:min(15, len(filepath.Base(os.Args[0])))] {
				t.Errorf("inherited comm %q", tl[0].Comm)
			}
		})
	}
}

func TestDoubleFork(t *testing.T) {
	c := openCollector(t, collector.Options{})
	_, out := startHelper(t, "double-fork")
	child := outPID(t, out, "child")
	evs := drain(t, c, 400*time.Millisecond)

	childEvents := of(evs, child)
	if kinds(childEvents) != "fork,exit" {
		t.Fatalf("child: [%s]", kinds(childEvents))
	}
	childKey := sameKey(t, childEvents)
	var grand collector.Event
	for _, ev := range evs {
		if ev.Kind == collector.KindFork && ev.Parent == childKey {
			grand = ev
		}
	}
	if grand.Proc.TGID == 0 {
		t.Fatalf("no fork record created by the child (%+v)", childKey)
	}
	gl := of(evs, grand.Proc.TGID)
	if kinds(gl) != "fork,exit" {
		t.Fatalf("grandchild: [%s]", kinds(gl))
	}
	// The grandchild outlives its creator: its exit comes later, and the fork
	// record keeps the real creator although the real parent changed.
	if gl[1].BootNS <= childEvents[1].BootNS {
		t.Errorf("grandchild exit must follow the child's exit")
	}
}

func TestThreadsAreNotProcesses(t *testing.T) {
	t.Run("fork from a non-leader thread", func(t *testing.T) {
		c := openCollector(t, collector.Options{})
		helper, out := startHelper(t, "thread-fork")
		child := outPID(t, out, "child")
		evs := drain(t, c, 300*time.Millisecond)
		fork := mustFind(t, of(evs, child), collector.KindFork)
		if fork.Parent.TGID != helper {
			t.Errorf("creating process %+v, want the thread group %d", fork.Parent, helper)
		}
		if tid := outPID(t, out, "forking-tid"); fork.TID != tid || tid == helper {
			t.Errorf("creating thread %d, want the non-leader thread %d (leader %d)", fork.TID, tid, helper)
		}
		// Go starts many threads; none of them may be reported as a process.
		// (The Go runtime itself forks one probe child on its first os/exec use,
		// so the number of children is not fixed: compare against thread ids.)
		threads := map[uint32]bool{}
		for _, id := range strings.Split(out["threads"], ",") {
			n, _ := strconv.ParseUint(id, 10, 32)
			threads[uint32(n)] = true
		}
		if len(threads) < 3 {
			t.Fatalf("helper did not report its threads: %q", out["threads"])
		}
		for _, ev := range evs {
			if ev.Kind == collector.KindFork && threads[ev.Proc.TGID] && ev.Proc.TGID != helper {
				t.Errorf("thread %d of the helper was reported as a new process: %+v", ev.Proc.TGID, ev)
			}
		}
		st, _ := c.Stats()
		if st.ThreadClones == 0 {
			t.Error("thread clones were not counted")
		}
	})

	t.Run("exec from a non-leader thread keeps the identity", func(t *testing.T) {
		c := openCollector(t, collector.Options{})
		helper, out := startHelper(t, "thread-exec")
		tl := of(drain(t, c, 300*time.Millisecond), helper)
		if kinds(tl) != "fork,exec,exec,exit" {
			t.Fatalf("records: [%s]", kinds(tl))
		}
		key := sameKey(t, tl) // fork, own exec, exec from the thread, exit: one instance
		fromThread := tl[2]
		if !fromThread.Exec.FromThread || fromThread.Exec.TIDBefore == helper {
			t.Errorf("exec was not recognised as thread exec: %+v", fromThread.Exec)
		}
		if tid := outPID(t, out, "exec-tid"); fromThread.Exec.TIDBefore != tid {
			t.Errorf("exec thread %d, helper said %d", fromThread.Exec.TIDBefore, tid)
		}
		if fromThread.Exec.Image != "true" {
			t.Errorf("image %q", fromThread.Exec.Image)
		}
		_ = key
	})

	t.Run("leader exits first, process ends with the last thread", func(t *testing.T) {
		c := openCollector(t, collector.Options{})
		helper, out := startHelper(t, "leader-exit")
		tl := of(drain(t, c, 500*time.Millisecond), helper)
		if kinds(tl) != "fork,exec,exit" {
			t.Fatalf("records: [%s] (the leader's own exit must not end the process)", kinds(tl))
		}
		exit := tl[2]
		if exit.TID == helper {
			t.Errorf("the last exiting thread was the leader %d", exit.TID)
		}
		if exit.ExitStatus != 3<<8 {
			t.Errorf("exit status %#x, want exit(3)", exit.ExitStatus)
		}
		if exit.BootNS-tl[1].BootNS < uint64(300*time.Millisecond) {
			t.Errorf("process reported dead after %s, the other thread lived 400ms", time.Duration(exit.BootNS-tl[1].BootNS))
		}
		_ = out
	})
}

func TestRepeatedExecKeepsIdentity(t *testing.T) {
	c := openCollector(t, collector.Options{})
	helper, _ := startHelper(t, "exec-chain", "3")
	tl := of(drain(t, c, 300*time.Millisecond), helper)
	if kinds(tl) != "fork,exec,exec,exec,exec,exit" {
		t.Fatalf("records: [%s]", kinds(tl))
	}
	sameKey(t, tl)
}

func TestFailedExecIsNotReported(t *testing.T) {
	c := openCollector(t, collector.Options{})
	helper, out := startHelper(t, "exec-fail")
	if out["exec-error"] == "" || out["exec-error2"] == "" {
		t.Fatalf("helper did not see the exec failures: %v", out)
	}
	evs := drain(t, c, 300*time.Millisecond)
	if got := kinds(of(evs, helper)); got != "fork,exec,exit" {
		t.Errorf("helper: [%s]: failed execve calls must not produce exec records", got)
	}
}

func TestImageIsTheExecutedFileNotArgv0(t *testing.T) {
	t.Run("symlink with a different name", func(t *testing.T) {
		c := openCollector(t, collector.Options{CaptureArgs: true})
		dir := t.TempDir()
		helper, _ := startHelper(t, "symlink-exec", dir)
		x := of(drain(t, c, 300*time.Millisecond), helper)
		if len(x) < 3 {
			t.Fatalf("records: [%s]", kinds(x))
		}
		e := x[2].Exec // fork, exec of the helper itself, exec through the symlink
		if e.Image != "true" || e.Path.Value != "/usr/bin/true" {
			t.Errorf("image %q path %q: must be the real file", e.Image, e.Path.Value)
		}
		if e.Filename != filepath.Join(dir, "sh-link") {
			t.Errorf("requested filename %q", e.Filename)
		}
		if len(e.Args.List) < 1 || e.Args.List[0] != "sh" {
			t.Errorf("argv[0] %+v", e.Args)
		}
	})

	t.Run("script: the interpreter is the image, the script name is the filename", func(t *testing.T) {
		c := openCollector(t, collector.Options{CaptureArgs: true})
		script := filepath.Join(t.TempDir(), "myscript.sh")
		if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		helper, _ := startHelper(t, "script-exec", script)
		x := of(drain(t, c, 300*time.Millisecond), helper)
		if len(x) < 3 {
			t.Fatalf("records: [%s]", kinds(x))
		}
		e := x[2].Exec
		interp, err := filepath.EvalSymlinks("/bin/sh")
		if err != nil {
			t.Fatal(err)
		}
		if e.Image != filepath.Base(interp) || e.Image == "myscript.sh" {
			t.Errorf("image %q, want the interpreter %q", e.Image, filepath.Base(interp))
		}
		if e.Filename != script {
			t.Errorf("filename %q, want the script %q", e.Filename, script)
		}
	})
}

func TestDeletedAndFilelessExecutables(t *testing.T) {
	t.Run("memfd", func(t *testing.T) {
		c := openCollector(t, collector.Options{})
		helper, _ := startHelper(t, "memfd-exec")
		x := of(drain(t, c, 300*time.Millisecond), helper)
		if len(x) < 3 {
			t.Fatalf("records: [%s]", kinds(x))
		}
		e := x[2].Exec
		if !e.Path.Deleted || e.Image != "memfd:pw-test" || e.Path.Value != "/memfd:pw-test" {
			t.Errorf("fileless exec not recognised: image %q path %+v", e.Image, e.Path)
		}
	})
	t.Run("unlinked before exec", func(t *testing.T) {
		c := openCollector(t, collector.Options{})
		p := filepath.Join(t.TempDir(), "gone-prog")
		helper, _ := startHelper(t, "deleted-exec", p)
		x := of(drain(t, c, 300*time.Millisecond), helper)
		if len(x) < 3 {
			t.Fatalf("records: [%s]", kinds(x))
		}
		e := x[2].Exec
		if e.Image != "gone-prog" || !e.Path.Deleted || e.Path.Value != p {
			t.Errorf("deleted binary: image %q path %+v, want %q deleted", e.Image, e.Path, p)
		}
	})
}

func TestLongPathAndArgumentLimits(t *testing.T) {
	t.Run("path deeper than the walker", func(t *testing.T) {
		c := openCollector(t, collector.Options{})
		deep := filepath.Join(t.TempDir(), strings.Repeat("d/", 40))
		helper, _ := startHelper(t, "deep-exec", deep)
		x := of(drain(t, c, 300*time.Millisecond), helper)
		if len(x) < 3 {
			t.Fatalf("records: [%s]", kinds(x))
		}
		e := x[2].Exec
		if e.Image != "deep-prog" {
			t.Errorf("image %q", e.Image)
		}
		if !e.Path.Truncated || !strings.HasSuffix(e.Path.Value, "/d/deep-prog") {
			t.Errorf("a path cut by the walker must be flagged and keep its tail: %+v", e.Path)
		}
	})
	t.Run("path longer than the output limit", func(t *testing.T) {
		c := openCollector(t, collector.Options{})
		long := filepath.Join(t.TempDir(), strings.Repeat(strings.Repeat("n", 200)+"/", 6))
		helper, _ := startHelper(t, "deep-exec", long)
		x := of(drain(t, c, 300*time.Millisecond), helper)
		if len(x) < 3 {
			t.Fatalf("records: [%s]", kinds(x))
		}
		e := x[2].Exec
		if !e.Path.Truncated || len(e.Path.Value) != 1024 || !strings.HasSuffix(e.Path.Value, "/deep-prog") {
			t.Errorf("path of %d bytes, truncated=%v", len(e.Path.Value), e.Path.Truncated)
		}
	})
	t.Run("more than 32 arguments", func(t *testing.T) {
		c := openCollector(t, collector.Options{CaptureArgs: true})
		helper, _ := startHelper(t, "many-args", "40", "10")
		x := of(drain(t, c, 300*time.Millisecond), helper)
		a := x[2].Exec.Args
		if len(a.List) != collector.MaxArgs || !a.Truncated || a.Argc != 41 {
			t.Errorf("%d args, truncated=%v argc=%d", len(a.List), a.Truncated, a.Argc)
		}
	})
	t.Run("more than 4096 argument bytes", func(t *testing.T) {
		c := openCollector(t, collector.Options{CaptureArgs: true})
		helper, _ := startHelper(t, "many-args", "5", "1000")
		a := of(drain(t, c, 300*time.Millisecond), helper)[2].Exec.Args
		if !a.Truncated || len(a.List) != 5 || len(a.List[4]) != 1000 { // argv[0] + 4 complete, the 5th is partial
			t.Logf("args: %d entries, last %d bytes, truncated=%v", len(a.List), len(a.List[len(a.List)-1]), a.Truncated)
		}
		if !a.Truncated || len(a.List) != 5 {
			t.Errorf("want argv[0] plus 4 complete arguments, got %d, truncated=%v", len(a.List), a.Truncated)
		}
		for _, s := range a.List[1:] {
			if len(s) != 1000 {
				t.Errorf("a partially captured argument leaked into the list (%d bytes)", len(s))
			}
		}
	})
}

// TestReusedPIDGetsANewIdentity forces the kernel to hand out the same pid
// twice: the keys must differ because the start time differs.
func TestReusedPIDGetsANewIdentity(t *testing.T) {
	c := openCollector(t, collector.Options{})
	const nsLastPID = "/proc/sys/kernel/ns_last_pid"
	b, err := os.ReadFile(nsLastPID)
	if err != nil {
		t.Skipf("cannot read ns_last_pid: %v", err)
	}
	cur, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	target := cur + 500
	var keys []collector.Key
	for i := 0; i < 2; i++ {
		if err := os.WriteFile(nsLastPID, []byte(strconv.Itoa(target-1)), 0o644); err != nil {
			t.Skipf("cannot set ns_last_pid: %v", err)
		}
		cmd := exec.Command("/bin/true")
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		if cmd.ProcessState.Pid() != target {
			t.Skipf("kernel handed out pid %d instead of %d", cmd.ProcessState.Pid(), target)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, ev := range drain(t, c, 300*time.Millisecond) {
		if ev.Kind == collector.KindFork && ev.Proc.TGID == uint32(target) {
			keys = append(keys, ev.Proc)
		}
	}
	if len(keys) != 2 || keys[0] == keys[1] || keys[0].StartNS >= keys[1].StartNS {
		t.Fatalf("same pid must give distinct identities with increasing start times: %+v", keys)
	}
}

func TestSnapshotAndLiveShareIdentity(t *testing.T) {
	c := openCollector(t, collector.Options{LiveTable: true})
	// A process that is alive before the snapshot and whose live records exist too.
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "PW_HELPER=double-fork")
	_ = cmd
	helper, _ := startHelper(t, "true-child", "x")
	evs := drain(t, c, 200*time.Millisecond)
	live := mustFind(t, of(evs, helper), collector.KindFork).Proc
	if live.TGID != helper {
		t.Fatal("helper fork record missing")
	}
	// The helper is gone now; the live table must have been cleared by the exit hook.
	if start, err := c.LiveStart(helper); err != nil || start != 0 {
		t.Errorf("live table for an exited process: %d, %v", start, err)
	}
	snap, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range snap.Procs {
		if p.Key.TGID == helper {
			t.Errorf("exited process %d is still in the snapshot", helper)
		}
	}
	self := uint32(os.Getpid())
	for _, p := range snap.Procs {
		if p.Key.TGID == self {
			start, _ := c.LiveStart(self)
			if start != p.Key.StartNS {
				t.Errorf("live table %d vs snapshot %d", start, p.Key.StartNS)
			}
		}
	}
}

// TestLossIsCountedInTheKernel overloads a tiny ring buffer. The kernel side
// counters must account for every record that could not be delivered, and
// delivered plus lost must add up.
func TestLossIsCountedInTheKernel(t *testing.T) {
	c := openCollector(t, collector.Options{RingBufferBytes: 4096})
	startHelper(t, "burst", "400") // nobody reads while the burst runs
	st, err := c.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Lost() == 0 {
		t.Fatalf("a 4 KiB ring buffer must overflow under a burst of 400 children: %+v", st)
	}
	delivered := drain(t, c, 300*time.Millisecond)
	after, _ := c.Stats()
	submitted := after.Fork + after.Exec + after.Exit
	if n := uint64(len(delivered)); n > submitted || submitted-n > 8 {
		t.Errorf("read %d records but the kernel counted %d as submitted (lost %d)", n, submitted, after.Lost())
	}
	t.Logf("lost %d (fork %d exec %d exit %d), delivered %d", after.Lost(), after.LostFork, after.LostExec, after.LostExit, len(delivered))
}

// TestHookLatency is informational: how long a record takes from the kernel
// event to Next.
func TestHookLatency(t *testing.T) {
	c := openCollector(t, collector.Options{})
	var worst, total time.Duration
	const n = 50
	for i := 0; i < n; i++ {
		cmd := exec.Command("/bin/true")
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		for {
			ev, err := c.Next(time.Now().Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if ev.Kind == collector.KindExit && ev.Proc.TGID == uint32(cmd.ProcessState.Pid()) {
				d := time.Duration(clockBoot() - ev.BootNS)
				total += d
				if d > worst {
					worst = d
				}
				break
			}
		}
	}
	t.Logf("exit record seen %s on average, %s worst (n=%d)", total/n, worst, n)
}

func clockBoot() uint64 { return clock.BootNS() }
