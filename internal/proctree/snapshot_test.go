package proctree

import (
	"testing"

	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/event"
)

func snapProc(k, parent collector.Key, visit uint64, image, path string) collector.SnapProc {
	return collector.SnapProc{
		Key: k, Parent: parent, VisitNS: visit, UID: 33, EUID: 33, GID: 33, Threads: 1,
		Comm: image, Image: image, ImageOK: true, Path: collector.Path{Value: path, Known: true},
	}
}

func snapshot(start, end uint64, procs ...collector.SnapProc) *collector.Snapshot {
	return &collector.Snapshot{StartNS: start, EndNS: end, Procs: procs}
}

func (h *harness) apply(snap *collector.Snapshot, pending []collector.Event, mode string) SnapshotResult {
	h.t.Helper()
	res, err := h.e.ApplySnapshot(snap, pending, mode)
	if err != nil {
		h.t.Fatal(err)
	}
	return res
}

func TestStartupDiscoversRootAndLivingDescendants(t *testing.T) {
	h := newHarness(t)
	worker := key(1201, 8_000_100_000_000)
	unrelated := key(900, 7_000_000_000_000)
	snap := snapshot(10_000_000_000_000, 10_000_000_100_000,
		snapProc(key(1, 1), key(0, 0), 10_000_000_000_001, "systemd", "/usr/lib/systemd/systemd"),
		snapProc(unrelated, key(1, 1), 10_000_000_000_002, "sshd", "/usr/sbin/sshd"),
		snapProc(master, key(1, 1), 10_000_000_000_003, "nginx", "/usr/sbin/nginx"),
		snapProc(worker, master, 10_000_000_000_004, "nginx", "/usr/sbin/nginx"), // matches too, but is a descendant
		snapProc(shell, worker, 10_000_000_000_005, "dash", "/usr/bin/dash"),
		snapProc(curl, shell, 10_000_000_000_006, "curl", "/usr/bin/curl"),
		snapProc(key(901, 7_000_000_000_001), unrelated, 10_000_000_000_007, "bash", "/usr/bin/bash"), // below an unrelated process
	)
	res := h.apply(snap, nil, DiscoveryStartup)
	if res.Roots != 1 || res.Descendants != 3 {
		t.Fatalf("result %+v", res)
	}
	h.expect("process.discovered:1200 process.discovered:1201 process.discovered:1235 process.discovered:1300")

	root, w, sh, cu := h.rec.events[0], h.rec.events[1], h.rec.events[2], h.rec.events[3]
	if root.Lineage.Role != event.RoleRoot || root.Source != event.SourceSnapshot || root.Process.ImageState != event.StateSnapshot {
		t.Errorf("root %+v %+v", root.Lineage, root.Process)
	}
	if root.Parent == nil || root.Parent.RelationshipSource != event.RelSnapshotPPID || *root.Parent.Image != "systemd" {
		t.Errorf("a discovered root keeps its current parent and says where it comes from: %+v", root.Parent)
	}
	for _, ev := range []*event.Event{w, sh, cu} {
		if ev.Root.PID != 1200 || ev.Parent.RelationshipSource != event.RelSnapshotPPID || !ev.Lineage.Complete {
			t.Errorf("pid %d: root %+v parent %+v lineage %+v", ev.Process.PID, ev.Root, ev.Parent, ev.Lineage)
		}
	}
	if cu.Lineage.Depth != 3 || sh.Lineage.Depth != 2 || w.Lineage.Depth != 1 {
		t.Errorf("depths %d %d %d", w.Lineage.Depth, sh.Lineage.Depth, cu.Lineage.Depth)
	}
	d := root.Details.(*event.DiscoveredDetails)
	if d.Discovery != "startup" || d.VisitBootNS != "10000000000003" || d.ExecIndex != 0 {
		t.Errorf("details %+v", d)
	}
	if root.BootTimeNS == nil || *root.BootTimeNS != "10000000000003" {
		t.Errorf("a discovery is timestamped with the snapshot visit, not an invented fork time: %v", root.BootTimeNS)
	}
	// Discovery happens once: the periodic reconciliation must not repeat it.
	h2 := len(h.rec.events)
	h.apply(snapshot(11_000_000_000_000, 11_000_000_100_000, snap.Procs...), nil, DiscoveryReconcile)
	if len(h.rec.events) != h2 {
		t.Errorf("repeated snapshot produced events: %s", h.rec.describe())
	}
}

func TestStartupDoesNotInventAncestry(t *testing.T) {
	h := newHarness(t)
	// A matching process whose parent is unknown (already gone): an independent root with unknown ancestry.
	orphan := snapProc(master, key(0, 0), 10_000_000_000_001, "nginx", "/usr/sbin/nginx")
	h.apply(snapshot(10_000_000_000_000, 10_000_000_100_000, orphan), nil, DiscoveryStartup)
	ev := h.last()
	if ev.Parent != nil || ev.Lineage.Complete {
		t.Errorf("unknown ancestry must be marked: parent %+v lineage %+v", ev.Parent, ev.Lineage)
	}
}

func TestForkDuringTheSnapshotIsNotDuplicated(t *testing.T) {
	h := newHarness(t)
	child := key(1210, 10_000_000_050_000)
	// The iterator saw the root and the new child (visited a moment after its birth); the fork record sits in the buffer.
	snap := snapshot(10_000_000_000_000, 10_000_000_100_000,
		snapProc(master, key(1, 1), 10_000_000_000_001, "nginx", "/usr/sbin/nginx"),
		snapProc(child, master, 10_000_000_060_000, "nginx", "/usr/sbin/nginx"),
	)
	pending := []collector.Event{
		forkEv(master, child, 10_000_000_050_000),
		execEv(child, master, 10_000_000_055_000, "dash", "/usr/bin/dash"), // exec that happened before the visit
		forkEv(child, curl, 10_000_000_070_000),                            // grandchild born after the visit
		exitEv(curl, 10_000_000_080_000, 0),
	}
	res := h.apply(snap, pending, DiscoveryStartup)
	if res.Roots != 1 || res.Descendants != 0 || res.Replayed != 4 {
		t.Fatalf("result %+v", res)
	}
	// The child's whole life is reported from the records (a real fork, not a discovery); nothing twice.
	h.expect("process.discovered:1200 process.fork:1210 process.exec:1210 process.fork:1300 process.exit:1300")
	if h.e.Lookup(curl) != nil || h.e.Lookup(child) == nil {
		t.Error("state after replay")
	}
}

// A snapshot record of a process that exited while the snapshot was taken is
// followed by its exit record in the buffer: the process must end up dead and
// must not be reported alive.
func TestSnapshotNeverResurrectsAnExitedProcess(t *testing.T) {
	h := newHarness(t)
	h.startNginx(master, 8_000_000_000_001)
	h.apply(snapshot(9_000_000_050_000, 9_000_000_200_000,
		snapProc(master, key(1, 1), 9_000_000_050_001, "nginx", "/usr/sbin/nginx"),
		snapProc(shell, master, 9_000_000_050_002, "nginx", "/usr/sbin/nginx")),
		[]collector.Event{exitEv(shell, 9_000_000_100_000, 0)}, DiscoveryReconcile)
	if h.e.Lookup(shell) != nil {
		t.Error("a snapshot record older than the buffered exit must not leave the process alive")
	}
	if got := h.rec.describe(); got != "process.exec:1200 process.discovered:1235 process.exit:1235" {
		t.Errorf("events: %s", got)
	}
}

func TestPreVisitExecIsAlreadyReflected(t *testing.T) {
	h := newHarness(t)
	child := key(1210, 10_000_000_050_000)
	h.startNginx(master, 8_000_000_000_001)
	// The child (fork before the agent) exec'ed to sh at ...055; the snapshot visited it at ...060 and shows sh.
	snap := snapshot(10_000_000_000_000, 10_000_000_100_000,
		snapProc(master, key(1, 1), 10_000_000_000_001, "nginx", "/usr/sbin/nginx"),
		snapProc(child, master, 10_000_000_060_000, "dash", "/usr/bin/dash"))
	pending := []collector.Event{
		execEv(child, master, 10_000_000_055_000, "dash", "/usr/bin/dash"), // reflected by the snapshot record
		execEv(child, master, 10_000_000_070_000, "curl", "/usr/bin/curl"), // after the visit: a real event
	}
	h.apply(snap, pending, DiscoveryReconcile)
	execs := h.rec.ofType(event.TypeProcessExec)
	if len(execs) != 2 || execs[1].Details.(*event.ExecDetails).ExecIndex != 1 || *execs[1].Details.(*event.ExecDetails).PreviousImage != "dash" {
		t.Errorf("events: %s", h.rec.describe())
	}
}

func TestReconcileInfersExitsWithoutInventingStatus(t *testing.T) {
	h := newHarness(t)
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, shell, 9_000_000_000_001), forkEv(master, curl, 20_000_000_000_001))
	// The exit record of the shell was lost; the curl child is too young to judge.
	snap := snapshot(20_000_000_000_000, 20_000_000_100_000,
		snapProc(master, key(1, 1), 20_000_000_000_002, "nginx", "/usr/sbin/nginx"))
	res := h.apply(snap, nil, DiscoveryReconcile)
	if res.InferredExits != 1 || h.e.Lookup(shell) != nil || h.e.Lookup(curl) == nil {
		t.Fatalf("result %+v", res)
	}
	ev := h.last()
	d := ev.Details.(*event.ExitDetails)
	if ev.EventType != event.TypeProcessExit || ev.Source != event.SourceSnapshot || d.ExitSource != "inferred" ||
		d.ExitCode != nil || d.Signal != nil || d.CoreDumped != nil || d.DurationNS != nil {
		t.Errorf("an inferred exit must not carry invented values: %+v", d)
	}
	if !ev.DataQuality.CollectionGap || len(ev.DataQuality.MissingFields) != 3 {
		t.Errorf("quality %+v", ev.DataQuality)
	}
}

func TestReconcileAfterLossMarksWhatItDiscovers(t *testing.T) {
	h := newHarness(t)
	h.startNginx(master, 8_000_000_000_001)
	h.e.MarkGap() // the application saw lost records
	snap := snapshot(20_000_000_000_000, 20_000_000_100_000,
		snapProc(master, key(1, 1), 20_000_000_000_001, "nginx", "/usr/sbin/nginx"),
		snapProc(shell, master, 20_000_000_000_002, "dash", "/usr/bin/dash"))
	h.apply(snap, nil, DiscoveryReconcile)
	ev := h.last()
	if ev.EventType != event.TypeProcessDiscovered || ev.Lineage.Complete || !ev.DataQuality.CollectionGap {
		t.Errorf("a process found after a loss has an unconfirmed lineage: %+v %+v", ev.Lineage, ev.DataQuality)
	}
	if h.e.GapOpen() {
		t.Error("the reconciliation closes the gap")
	}
	// A process admitted later through a normal fork is fine again.
	other := key(1500, 21_000_000_000_000)
	h.handle(forkEv(master, other, 21_000_000_000_001))
	if ev := h.last(); !ev.Lineage.Complete || ev.DataQuality.CollectionGap {
		t.Errorf("fork after the gap: %+v", ev.Lineage)
	}
}

func TestSnapshotArgumentsComeFromTheProvider(t *testing.T) {
	calls := 0
	h := newHarness(t, func(o *Options) {
		o.CaptureArgv = true
		o.SnapshotArgs = func(k collector.Key) collector.Args {
			calls++
			if k == shell {
				return collector.Args{State: collector.ArgsFailed} // identity check failed or process gone
			}
			return collector.Args{State: collector.ArgsCaptured, List: []string{"nginx", "-g", "daemon off;"}}
		}
	})
	h.apply(snapshot(10_000_000_000_000, 10_000_000_100_000,
		snapProc(master, key(1, 1), 10_000_000_000_001, "nginx", "/usr/sbin/nginx"),
		snapProc(shell, master, 10_000_000_000_002, "dash", "/usr/bin/dash")), nil, DiscoveryStartup)
	if calls != 2 {
		t.Errorf("provider called %d times", calls)
	}
	root, sh := h.rec.events[0], h.rec.events[1]
	if root.Process.ArgvState == nil || *root.Process.ArgvState != event.StateSnapshot || len(root.Process.Argv) != 3 {
		t.Errorf("root argv %+v", root.Process)
	}
	if sh.Process.Argv != nil || len(sh.DataQuality.MissingFields) != 1 || sh.DataQuality.MissingFields[0].Reason != event.ReasonProcUnavailable {
		t.Errorf("a failed /proc read is null with a reason, not an empty list: %+v", sh.DataQuality)
	}
}
