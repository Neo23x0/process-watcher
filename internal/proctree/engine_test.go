package proctree

import (
	"strings"
	"testing"

	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/filter"
)

var (
	master = key(1200, 8_000_000_000_000)
	helper = key(1210, 8_100_000_000_000)
	shell  = key(1235, 9_000_000_000_000)
	curl   = key(1300, 9_100_000_000_000)
)

func TestRootStartsLater(t *testing.T) {
	h := newHarness(t)
	// An unrelated process starts and ends: nothing is reported.
	other := key(900, 7_000_000_000_000)
	h.handle(execEv(other, key(1, 1), 7_000_000_000_001, "python3", "/usr/bin/python3.12", "python3", "nginx-is-only-an-argument"))
	h.handle(exitEv(other, 7_100_000_000_000, 0))
	h.expect("")

	h.startNginx(master, 8_000_000_000_001)
	h.expect("process.exec:1200")
	ev := h.last()
	if ev.Lineage.Role != event.RoleRoot || ev.Lineage.Depth != 0 || len(ev.Lineage.Ancestors) != 0 || !ev.Lineage.Complete {
		t.Errorf("lineage %+v", ev.Lineage)
	}
	if ev.Root.ProcessID != ev.Process.ProcessID || *ev.Root.Image != "nginx" {
		t.Errorf("a root references itself: %+v", ev.Root)
	}
	if ev.Source != event.SourceEBPF || ev.Process.ImageState != event.StateExecuted {
		t.Errorf("source %s state %s", ev.Source, ev.Process.ImageState)
	}
	if ev.Parent == nil || ev.Parent.RelationshipSource != event.RelExecParent || ev.Parent.PID != 1 {
		t.Errorf("a root started by the kernel's real parent keeps that excerpt: %+v", ev.Parent)
	}
	if d := ev.Details.(*event.ExecDetails); d.ExecIndex != 1 || d.PreviousImage != nil || *d.ExecFilename != "/usr/sbin/nginx" {
		t.Errorf("details %+v", d)
	}
}

func TestEveryGenerationSharesTheRoot(t *testing.T) {
	h := newHarness(t)
	h.startNginx(master, 8_000_000_000_001)
	h.handle(
		forkEv(master, helper, 8_100_000_000_001),
		execEv(helper, master, 8_100_000_000_002, "legitimate-helper", "/opt/helper/legitimate-helper"),
		forkEv(helper, shell, 9_000_000_000_001),
		execEv(shell, helper, 9_000_000_000_002, "dash", "/usr/bin/dash", "sh", "-c", "curl x"),
		forkEv(shell, curl, 9_100_000_000_001),
		execEv(curl, shell, 9_100_000_000_002, "curl", "/usr/bin/curl", "curl", "x"),
	)
	var wantDepth = map[uint32]int{1210: 1, 1235: 2, 1300: 3}
	rootID := h.rec.events[0].Process.ProcessID
	for _, ev := range h.rec.events[1:] {
		pid := ev.Process.PID
		if ev.Root.ProcessID != rootID || ev.Lineage.Role != event.RoleDescendant || ev.Lineage.Depth != wantDepth[pid] {
			t.Errorf("%s pid %d: root %s depth %d role %s", ev.EventType, pid, ev.Root.ProcessID, ev.Lineage.Depth, ev.Lineage.Role)
		}
		if len(ev.Lineage.Ancestors) != ev.Lineage.Depth || ev.Lineage.Ancestors[0] != rootID {
			t.Errorf("pid %d ancestors %v", pid, ev.Lineage.Ancestors)
		}
	}
	last := h.last() // curl: root nginx -> helper -> sh -> curl
	if got := last.Lineage.Ancestors; len(got) != 3 || !strings.HasSuffix(got[1], ":1210:8100000000000") || !strings.HasSuffix(got[2], ":1235:9000000000000") {
		t.Errorf("ancestors root first, direct parent last: %v", got)
	}
	if last.Parent.PID != 1235 || *last.Parent.Image != "dash" || last.Parent.RelationshipSource != event.RelFork {
		t.Errorf("parent excerpt %+v", last.Parent)
	}
	// The root keeps the image it was admitted with.
	if *last.Root.Image != "nginx" {
		t.Errorf("root image %q", *last.Root.Image)
	}
}

func TestForkInheritsAndExecReplaces(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.CaptureArgv = true })
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, helper, 8_100_000_000_001))
	fork := h.last()
	if fork.EventType != event.TypeProcessFork || *fork.Process.Image != "nginx" || fork.Process.ImageState != event.StateInherited {
		t.Errorf("fork must inherit the creator's image: %+v", fork.Process)
	}
	if fork.Process.ArgvState == nil || *fork.Process.ArgvState != event.StateInherited || len(fork.Process.Argv) != 3 {
		t.Errorf("inherited arguments must be marked: %v %v", fork.Process.Argv, fork.Process.ArgvState)
	}
	if fork.Details.(*event.ForkDetails).CreatorTID != master.TGID {
		t.Errorf("creator tid %+v", fork.Details)
	}

	h.handle(execEv(helper, master, 8_100_000_000_002, "dash", "/usr/bin/dash", "sh"))
	ex := h.last()
	if *ex.Process.Image != "dash" || ex.Process.ImageState != event.StateExecuted || *ex.Process.ArgvState != event.StateExecuted {
		t.Errorf("exec state %+v", ex.Process)
	}
	if d := ex.Details.(*event.ExecDetails); d.ExecIndex != 1 || *d.PreviousImage != "nginx" {
		t.Errorf("details %+v", d)
	}
}

func TestForkWithoutExecHasItsOwnLifecycle(t *testing.T) {
	h := newHarness(t)
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, helper, 8_100_000_000_001), exitEv(helper, 8_100_000_500_000, 7<<8))
	h.expect("process.exec:1200 process.fork:1210 process.exit:1210")
	d := h.last().Details.(*event.ExitDetails)
	if d.ExitCode == nil || *d.ExitCode != 7 || d.Signal != nil || d.CoreDumped != nil || *d.DurationNS != "500000" || d.ExitSource != "kernel" {
		t.Errorf("exit details %+v (duration %v)", d, d.DurationNS)
	}
}

func TestExitStatusDecoding(t *testing.T) {
	for _, tc := range []struct {
		status int32
		code   *int
		sig    *int
		core   *bool
	}{
		{0, ptr(0), nil, nil},
		{1 << 8, ptr(1), nil, nil},
		{255 << 8, ptr(255), nil, nil},
		{9, nil, ptr(9), ptrB(false)},
		{11 | 0x80, nil, ptr(11), ptrB(true)},
	} {
		code, sig, core := decodeStatus(tc.status)
		if !eqInt(code, tc.code) || !eqInt(sig, tc.sig) || !eqBool(core, tc.core) {
			t.Errorf("status %#x: got %v %v %v", tc.status, code, sig, core)
		}
	}
}

func ptr(i int) *int    { return &i }
func ptrB(b bool) *bool { return &b }
func eqInt(a, b *int) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}
func eqBool(a, b *bool) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func TestRepeatedExecKeepsIdentityAndCounts(t *testing.T) {
	h := newHarness(t)
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, shell, 9_000_000_000_001),
		execEv(shell, master, 9_000_000_000_002, "dash", "/usr/bin/dash"),
		execEv(shell, master, 9_000_000_000_003, "curl", "/usr/bin/curl"),
		execEv(shell, master, 9_000_000_000_004, "id", "/usr/bin/id"))
	execs := h.rec.ofType(event.TypeProcessExec)[1:]
	for n, ev := range execs {
		if ev.Process.ProcessID != execs[0].Process.ProcessID {
			t.Errorf("identity changed across execs")
		}
		if got := ev.Details.(*event.ExecDetails).ExecIndex; got != n+1 {
			t.Errorf("exec %d has index %d", n, got)
		}
	}
	if prev := *execs[2].Details.(*event.ExecDetails).PreviousImage; prev != "curl" {
		t.Errorf("previous image %q", prev)
	}
}

func TestExclusionIsReevaluatedPerEvent(t *testing.T) {
	h := newHarness(t, func(o *Options) {
		o.Exclusions = filter.NewExclusions([]string{"legitimate-helper"}, nil, false)
	})
	h.startNginx(master, 8_000_000_000_001)
	h.handle(
		forkEv(master, helper, 8_100_000_000_001),                                                // inherited image nginx: reported
		execEv(helper, master, 8_100_000_000_002, "legitimate-helper", "/opt/legitimate-helper"), // excluded
		forkEv(helper, shell, 9_000_000_000_001),                                                 // inherited legitimate-helper: excluded
		execEv(shell, helper, 9_000_000_000_002, "dash", "/usr/bin/dash", "sh"),                  // the new image is evaluated again: reported
		forkEv(shell, curl, 9_100_000_000_001),
		execEv(curl, shell, 9_100_000_000_002, "curl", "/usr/bin/curl"),
	)
	var excluded []string
	for _, ev := range h.rec.events {
		if ev.Filter.Excluded {
			excluded = append(excluded, ev.EventType)
			if len(ev.Filter.Matches) != 1 || ev.Filter.Matches[0].Field != "image" || ev.Filter.Matches[0].Value != "legitimate-helper" {
				t.Errorf("matches %+v", ev.Filter.Matches)
			}
		}
	}
	if len(excluded) != 2 || excluded[0] != event.TypeProcessExec || excluded[1] != event.TypeProcessFork {
		t.Errorf("excluded events %v", excluded)
	}
	// Shell and curl stay visible and keep the root although their ancestor is excluded.
	for _, pid := range []uint32{1235, 1300} {
		var found bool
		for _, ev := range h.rec.events {
			if ev.Process.PID == pid && ev.EventType == event.TypeProcessExec && !ev.Filter.Excluded {
				found = true
			}
		}
		if !found {
			t.Errorf("pid %d must be reported", pid)
		}
	}
}

func TestExclusionOnArgumentsNeedsThem(t *testing.T) {
	h := newHarness(t, func(o *Options) {
		o.CaptureArgv = true
		o.Exclusions = filter.NewExclusions(nil, []string{"--health"}, false)
	})
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, shell, 9_000_000_000_001))
	h.handle(execEv(shell, master, 9_000_000_000_002, "curl", "/usr/bin/curl", "curl", "--healthcheck"))
	if ev := h.last(); !ev.Filter.Excluded || ev.Filter.Matches[0].Index == nil || *ev.Filter.Matches[0].Index != 1 {
		t.Errorf("argument exclusion: %+v", ev.Filter)
	}
	// A truncated argument list does not prove the string is absent, but never matches either.
	other := key(1400, 9_200_000_000_000)
	h.handle(forkEv(master, other, 9_200_000_000_001))
	ex := execEv(other, master, 9_200_000_000_002, "curl", "/usr/bin/curl", "curl")
	ex.Exec.Args.Truncated = true
	h.handle(ex)
	if ev := h.last(); ev.Filter.Excluded {
		t.Errorf("unproven match must not exclude: %+v", ev.Filter)
	}
	if ev := h.last(); len(ev.DataQuality.TruncatedFields) != 1 || ev.DataQuality.TruncatedFields[0] != "process.argv" {
		t.Errorf("data quality %+v", ev.DataQuality)
	}
}

func TestRootEndsChildSurvives(t *testing.T) {
	h := newHarness(t)
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, helper, 8_100_000_000_001), exitEv(master, 8_200_000_000_000, 0))
	// The orphan keeps forking: still in the original tree, with the historical parent chain.
	h.handle(forkEv(helper, shell, 9_000_000_000_001), execEv(shell, key(1, 1), 9_000_000_000_002, "dash", "/usr/bin/dash"))
	ev := h.last()
	if ev.Lineage.Depth != 2 || ev.Root.PID != 1200 || len(ev.Lineage.Ancestors) != 2 {
		t.Errorf("lineage %+v root %+v", ev.Lineage, ev.Root)
	}
	if ev.Parent.PID != 1210 || ev.Parent.RelationshipSource != event.RelFork {
		t.Errorf("the creator stays the parent although the real ppid changed: %+v", ev.Parent)
	}
	if st := h.e.Stats(); st.Roots != 0 || st.Instances != 2 {
		t.Errorf("stats %+v", st)
	}
}

func TestPIDReuseNeverInheritsState(t *testing.T) {
	h := newHarness(t)
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, shell, 9_000_000_000_001), exitEv(shell, 9_000_000_100_000, 0))
	before := len(h.rec.events)
	// The same tgid is handed out again to an unrelated process.
	reused := key(shell.TGID, 12_000_000_000_000)
	h.handle(execEv(reused, key(1, 1), 12_000_000_000_001, "python3", "/usr/bin/python3"), exitEv(reused, 12_100_000_000_000, 0))
	if len(h.rec.events) != before {
		t.Errorf("a reused pid must not be mistaken for the old instance: %s", h.rec.describe())
	}
	// And a reused pid below a tracked parent is a new instance.
	again := key(shell.TGID, 13_000_000_000_000)
	h.handle(forkEv(master, again, 13_000_000_000_001))
	ev := h.last()
	if ev.Process.ProcessID == h.rec.events[1].Process.ProcessID || ev.Process.StartBootNS != "13000000000000" {
		t.Errorf("new instance must have its own identity: %s", ev.Process.ProcessID)
	}
}

func TestTwoIndependentRoots(t *testing.T) {
	h := newHarness(t)
	second := key(2200, 8_500_000_000_000)
	h.startNginx(master, 8_000_000_000_001)
	h.handle(execEv(second, key(1, 1), 8_500_000_000_001, "nginx-debug", "/usr/sbin/nginx-debug"))
	h.handle(forkEv(second, shell, 9_000_000_000_001))
	if h.e.Stats().Roots != 2 {
		t.Fatalf("roots %d", h.e.Stats().Roots)
	}
	if ev := h.last(); ev.Root.PID != 2200 {
		t.Errorf("child of the second root points at %d", ev.Root.PID)
	}
	// A matching worker below the master is a descendant, never a second root.
	worker := key(1201, 8_000_100_000_000)
	h.handle(forkEv(master, worker, 8_000_100_000_001), execEv(worker, master, 8_000_100_000_002, "nginx", "/usr/sbin/nginx"))
	if ev := h.last(); ev.Lineage.Role != event.RoleDescendant || ev.Root.PID != 1200 {
		t.Errorf("worker %+v", ev.Lineage)
	}
	if h.e.Stats().Roots != 2 {
		t.Errorf("roots %d", h.e.Stats().Roots)
	}
}

func TestDepthLimitOnlyLimitsOutput(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxDepth = 1 })
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, helper, 8_100_000_000_001), // depth 1: reported
		forkEv(helper, shell, 9_000_000_000_001),                          // depth 2: not reported
		execEv(shell, helper, 9_000_000_000_002, "dash", "/usr/bin/dash"), // not reported
		forkEv(shell, curl, 9_100_000_000_001))                            // depth 3: not reported
	h.expect("process.exec:1200 process.fork:1210")
	if h.e.Stats().DepthSuppressed != 3 {
		t.Errorf("suppressed %d", h.e.Stats().DepthSuppressed)
	}
	// Tracking is unaffected: the exit of the deep process still resolves its instance.
	if h.e.Lookup(curl) == nil || h.e.Lookup(curl).Depth != 3 {
		t.Errorf("deep instance not tracked")
	}
}

func TestAncestorArrayIsBoundedButDepthIsNot(t *testing.T) {
	h := newHarness(t)
	h.startNginx(master, 8_000_000_000_001)
	parent := master
	var last *event.Event
	for d := 1; d <= 70; d++ {
		child := key(uint32(5000+d), uint64(9_000_000_000_000+d))
		h.handle(forkEv(parent, child, uint64(9_000_000_000_100+d)))
		last = h.last()
		parent = child
	}
	if last.Lineage.Depth != 70 || len(last.Lineage.Ancestors) != event.MaxAncestors || !last.Lineage.AncestorsTruncated {
		t.Fatalf("depth %d ancestors %d truncated %v", last.Lineage.Depth, len(last.Lineage.Ancestors), last.Lineage.AncestorsTruncated)
	}
	if !strings.Contains(last.Lineage.Ancestors[0], ":1200:") {
		t.Errorf("the root must be kept: %s", last.Lineage.Ancestors[0])
	}
	if !strings.Contains(last.Lineage.Ancestors[63], ":5069:") || !strings.Contains(last.Lineage.Ancestors[1], ":5007:") {
		t.Errorf("the nearest parents must be kept: [1]=%s [63]=%s", last.Lineage.Ancestors[1], last.Lineage.Ancestors[63])
	}
	// Internal tracking is not bounded by the serialization limit.
	if h.e.Lookup(parent).Depth != 70 {
		t.Errorf("internal depth %d", h.e.Lookup(parent).Depth)
	}
}

func TestMissingMetadataKeepsTheRecord(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.CaptureArgv = true })
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, shell, 9_000_000_000_001))
	ex := execEv(shell, master, 9_000_000_000_002, "dash", "")
	ex.Exec.Path = collector.Path{} // the kernel could not build the path
	ex.Exec.FilenameOK = false      // nor read the requested name
	ex.Exec.Args = collector.Args{State: collector.ArgsFailed}
	h.handle(ex)
	ev := h.last()
	if ev.Process.ImagePath != nil || ev.Process.Argv != nil || *ev.Process.Image != "dash" {
		t.Errorf("process %+v", ev.Process)
	}
	want := map[string]string{"process.image_path": event.ReasonKernelUnavailable, "process.argv": event.ReasonKernelUnavailable}
	for _, m := range ev.DataQuality.MissingFields {
		if want[m.Field] != m.Reason {
			t.Errorf("unexpected missing %+v", m)
		}
		delete(want, m.Field)
	}
	if len(want) != 0 {
		t.Errorf("missing entries not reported: %v", want)
	}
	if ev.Details.(*event.ExecDetails).ExecFilename != nil {
		t.Error("an unreadable filename must be null, not an empty string")
	}
}

func TestInvalidUTF8IsSanitizedAndFlagged(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.CaptureArgv = true })
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, shell, 9_000_000_000_001))
	h.handle(execEv(shell, master, 9_000_000_000_002, "dash", "/usr/bin/dash", "sh", "-c", "echo \xff\xfe"))
	ev := h.last()
	if ev.Process.Argv[2] != "echo ��" {
		t.Errorf("argv %q", ev.Process.Argv)
	}
	if len(ev.DataQuality.SanitizedFields) != 1 || ev.DataQuality.SanitizedFields[0] != "process.argv" {
		t.Errorf("sanitized %v", ev.DataQuality.SanitizedFields)
	}
	if line, err := ev.MarshalLine(); err != nil || strings.Count(string(line), "\n") != 1 {
		t.Errorf("not one line: %v %q", err, line)
	}
}

func TestProcessTableLimit(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxProcesses = 3 })
	h.startNginx(master, 8_000_000_000_001)
	a, b, c := key(2001, 9_000_000_000_001), key(2002, 9_000_000_000_002), key(2003, 9_000_000_000_003)
	h.handle(forkEv(master, a, 9_000_000_000_011), forkEv(master, b, 9_000_000_000_012))
	h.handle(forkEv(master, c, 9_000_000_000_013)) // table is full
	if h.e.Lookup(c) != nil || h.e.Stats().TableFull != 1 || !h.e.GapOpen() {
		t.Fatalf("limit not enforced: %+v", h.e.Stats())
	}
	if n := h.e.TakeNotices(); len(n) != 1 || n[0].Cause != "process_table_full" {
		t.Errorf("notices %+v", n)
	}
	// Finished and unreferenced entries are released and make room again.
	h.handle(exitEv(a, 9_500_000_000_000, 0))
	if h.e.Stats().Retained != 3-1 {
		t.Errorf("retained %d", h.e.Stats().Retained)
	}
	h.handle(forkEv(master, c, 9_600_000_000_001))
	if h.e.Lookup(c) == nil {
		t.Error("room was not freed")
	}
}

func TestDeadAncestorsAreRetainedWhileNeededThenReleased(t *testing.T) {
	h := newHarness(t)
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, helper, 8_100_000_000_001), forkEv(helper, shell, 9_000_000_000_001))
	h.handle(exitEv(master, 9_100_000_000_000, 0), exitEv(helper, 9_100_000_000_100, 0))
	if h.e.Stats().Retained != 3 {
		t.Fatalf("both dead ancestors are needed for the lineage of the shell: retained %d", h.e.Stats().Retained)
	}
	h.handle(exitEv(shell, 9_200_000_000_000, 0))
	if st := h.e.Stats(); st.Retained != 0 || st.Instances != 0 {
		t.Errorf("everything must be released at the end: %+v", st)
	}
}

func TestUnknownExecWithObservedParentIsGapAffected(t *testing.T) {
	h := newHarness(t)
	h.startNginx(master, 8_000_000_000_001)
	// The fork record was lost: the exec of an unknown instance names a tracked real parent.
	h.handle(execEv(shell, master, 9_000_000_000_002, "dash", "/usr/bin/dash"))
	ev := h.last()
	if ev.Lineage.Role != event.RoleDescendant || ev.Lineage.Complete || !ev.DataQuality.CollectionGap ||
		ev.Parent.RelationshipSource != event.RelExecParent {
		t.Errorf("lineage %+v quality %+v parent %+v", ev.Lineage, ev.DataQuality, ev.Parent)
	}
}

func TestEmitErrorIsFatal(t *testing.T) {
	h := newHarness(t)
	h.rec.err = errTest
	if err := h.e.HandleEvent(execEv(master, key(1, 1), 8_000_000_000_001, "nginx", "/usr/sbin/nginx")); err == nil {
		t.Fatal("a failing local log must abort processing")
	}
}

var errTest = &testError{}

type testError struct{}

func (*testError) Error() string { return "disk full" }

func TestRootAdmittedAtRuntimeAsksForAReconciliation(t *testing.T) {
	h := newHarness(t)
	if h.e.TakeReconcileHint() {
		t.Fatal("no hint without a new root")
	}
	// A process that was no root before execs into a matching program: it may already have
	// living children that no record told us about.
	h.startNginx(master, 8_000_000_000_001)
	if !h.e.TakeReconcileHint() || h.e.TakeReconcileHint() {
		t.Fatal("a root admitted by a live exec asks for one reconciliation")
	}
	// A discovery by snapshot does not.
	h.apply(snapshot(10_000_000_000_000, 10_000_000_100_000,
		snapProc(key(2200, 8_500_000_000_000), key(1, 1), 10_000_000_000_001, "nginx", "/usr/sbin/nginx")), nil, DiscoveryStartup)
	if h.e.TakeReconcileHint() {
		t.Fatal("snapshot discoveries need no further reconciliation")
	}
}
