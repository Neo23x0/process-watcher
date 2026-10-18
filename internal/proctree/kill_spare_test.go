package proctree

import (
	"testing"

	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/event"
)

// A service master forks its workers with its own image. A rule that matches that
// image therefore hits every worker at its fork, and without the guard the workers
// are killed (and re-forked by the master, endlessly).
func TestBroadRuleHitsForkedWorkersWithoutTheGuard(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"nginx"}, nil))
	worker := key(1301, 9_000_000_000_000)
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, worker, 9_000_000_000_001))
	if len(h.resp.submitted) != 1 || h.resp.submitted[0].Key != worker {
		t.Fatalf("the forked worker must be the target of the rule: %s", h.rec.describe())
	}
	if h.e.Stats().KillSpared != 0 {
		t.Error("nothing is spared without kill.spare_root_image")
	}
}

func TestSpareRootImageProtectsForkedWorkers(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"nginx"}, nil), func(o *Options) { o.KillSpareRootImage = true })
	worker := key(1301, 9_000_000_000_000)
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, worker, 9_000_000_000_001))

	if len(h.resp.submitted) != 0 || len(h.rec.ofType(event.TypeKillRequested)) != 0 {
		t.Fatalf("a worker that runs its root's image is never a target: %s", h.rec.describe())
	}
	if len(h.resp.skipped) != 1 || h.resp.skipped[0].reason != event.SkipRootImageSpared || h.resp.skipped[0].action.Key != worker {
		t.Fatalf("the spared decision must be reported: %+v", h.resp.skipped)
	}
	if got := h.e.Stats().KillSpared; got != 1 {
		t.Errorf("KillSpared = %d", got)
	}
	// One decision per instance and exec generation: the worker's later events do not repeat it.
	h.handle(exitEv(worker, 9_000_001_000_000, 0))
	if len(h.resp.skipped) != 1 {
		t.Errorf("the decision was repeated: %+v", h.resp.skipped)
	}
}

// What a worker starts is not the service itself: a program with another image is
// judged by the rules as before.
func TestSpareRootImageStillKillsWhatTheWorkerStarts(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"nginx"}, []string{`^useradd$`}), func(o *Options) { o.KillSpareRootImage = true })
	worker := key(1301, 9_000_000_000_000)
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, worker, 9_000_000_000_001))
	h.handle(forkEv(worker, shell, 9_100_000_000_001), execEv(shell, worker, 9_100_000_000_002, "useradd", "/usr/sbin/useradd", "useradd", "bob"))

	if len(h.resp.submitted) != 1 || h.resp.submitted[0].Key != shell {
		t.Fatalf("useradd must still be the target: %s", h.rec.describe())
	}
	// The fork of the shell inherited the worker's image: spared as well, and only the exec was acted on.
	if len(h.resp.skipped) != 2 {
		t.Fatalf("want the worker fork and the shell's inherited fork spared, got %+v", h.resp.skipped)
	}
}

// A master that re-executes itself on a reload and forks the new master: the new
// master is a descendant of the old root and must not be killed either.
func TestSpareRootImageProtectsTheReexecutedMaster(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"nginx"}, nil), func(o *Options) { o.KillSpareRootImage = true })
	newMaster := key(1400, 9_500_000_000_000)
	h.startNginx(master, 8_000_000_000_001)
	h.handle(execEv(master, key(1, 1), 9_400_000_000_001, "nginx", "/usr/sbin/nginx", "nginx"))
	h.handle(forkEv(master, newMaster, 9_500_000_000_001))
	h.handle(execEv(newMaster, master, 9_500_000_000_002, "nginx", "/usr/sbin/nginx", "nginx"))
	if len(h.resp.submitted) != 0 {
		t.Fatalf("the new master must not be killed: %s", h.rec.describe())
	}
}

// The comparison is by executable path when both are known: a program that merely
// has the same file name elsewhere is not the service.
func TestSpareRootImageComparesPaths(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"nginx"}, nil), func(o *Options) { o.KillSpareRootImage = true })
	impostor := key(1500, 9_000_000_000_000)
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, impostor, 9_000_000_000_001), execEv(impostor, master, 9_000_000_000_002, "nginx", "/tmp/dropper/nginx", "nginx"))

	if len(h.resp.submitted) != 1 || h.resp.submitted[0].Key != impostor || h.resp.submitted[0].ExecIndex != 1 {
		t.Fatalf("a different file with the same name is a target: %s", h.rec.describe())
	}
}

func TestSpareRootImageFallsBackToTheImageName(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"nginx"}, nil), func(o *Options) { o.KillSpareRootImage = true })
	worker := key(1301, 9_000_000_000_000)
	// A root whose path the kernel could not build.
	rootExec := execEv(master, key(1, 1), 8_000_000_000_001, "nginx", "/usr/sbin/nginx", "nginx")
	rootExec.Exec.Path = collector.Path{}
	h.handle(rootExec)
	h.handle(forkEv(master, worker, 9_000_000_000_001))
	if len(h.resp.submitted) != 0 || len(h.resp.skipped) != 1 {
		t.Fatalf("the image name decides when a path is unknown: %s %+v", h.rec.describe(), h.resp.skipped)
	}
}
