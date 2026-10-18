package proctree

import (
	"strings"
	"testing"

	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/event"
)

// The audit event of a decision lists the ancestors with their executables and arguments, so that
// it can be read without the events of the shell and the worker above the target.
func TestKillAuditListsTheAncestorsWithTheirArguments(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, nil, []string{`^python3$`}))
	worker := key(1301, 9_000_000_000_000)
	sh := key(1400, 9_100_000_000_000)
	py := key(1500, 9_200_000_000_000)
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, worker, 9_000_000_000_001))
	h.handle(forkEv(worker, sh, 9_100_000_000_001), execEv(sh, worker, 9_100_000_000_002, "dash", "/usr/bin/dash", "sh", "-c", "--", "python3 -c 'print(1)'"))
	h.handle(forkEv(sh, py, 9_200_000_000_001), execEv(py, sh, 9_200_000_000_002, "python3", "/usr/bin/python3", "python3", "-c", "print(1)"))

	if len(h.resp.submitted) != 1 {
		t.Fatalf("submitted %d: %s", len(h.resp.submitted), h.rec.describe())
	}
	d := h.last().Details.(*event.KillDetails)
	if d.ChainTruncated || len(d.Chain) != 3 {
		t.Fatalf("chain %+v truncated=%v", d.Chain, d.ChainTruncated)
	}
	wantImages := []string{"nginx", "nginx", "dash"} // the root, the worker (inherited image), the shell
	for i, l := range d.Chain {
		if l.Image == nil || *l.Image != wantImages[i] {
			t.Errorf("link %d image %v, want %s", i, l.Image, wantImages[i])
		}
	}
	root, shell := d.Chain[0], d.Chain[2]
	if root.PID != 1200 || root.ProcessID != h.rec.events[len(h.rec.events)-1].Root.ProcessID || root.ExecIndex != 1 {
		t.Errorf("root link %+v", root)
	}
	if got := strings.Join(shell.Argv, "|"); got != "sh|-c|--|python3 -c 'print(1)'" || shell.ArgvComplete == nil || !*shell.ArgvComplete || shell.ExecIndex != 1 {
		t.Errorf("shell link argv %q complete %v exec %d", got, shell.ArgvComplete, shell.ExecIndex)
	}
	if shell.PID != 1400 || shell.ImagePath == nil || *shell.ImagePath != "/usr/bin/dash" {
		t.Errorf("shell link %+v", shell)
	}
	// The same chain is in the result event.
	if got := len(h.last().Details.(*event.KillDetails).Chain); got != 3 {
		t.Errorf("kill_requested has %d links", got)
	}
}

func TestKillChainIsBounded(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, nil, []string{`^deep-target$`}))
	h.startNginx(master, 8_000_000_000_001)
	parent := master
	// A chain of 11 levels below the root: the audit keeps the root and the nearest seven ancestors.
	for k := 0; k < 11; k++ {
		child := key(uint32(2000+k), 9_000_000_000_000+uint64(k)*1000)
		h.handle(forkEv(parent, child, 9_000_000_000_001+uint64(k)*1000))
		parent = child
	}
	target := key(3000, 9_500_000_000_000)
	h.handle(forkEv(parent, target, 9_500_000_000_001), execEv(target, parent, 9_500_000_000_002, "deep-target", "/usr/bin/deep-target", "deep-target"))
	if len(h.resp.submitted) != 1 {
		t.Fatalf("%s", h.rec.describe())
	}
	d := h.last().Details.(*event.KillDetails)
	if !d.ChainTruncated || len(d.Chain) != chainMaxLinks {
		t.Fatalf("%d links, truncated=%v", len(d.Chain), d.ChainTruncated)
	}
	if d.Chain[0].PID != 1200 || d.Chain[len(d.Chain)-1].PID != 2010 || d.Chain[1].PID != 2004 {
		t.Errorf("the root and the nearest ancestors must be kept: %d ... %d, second %d", d.Chain[0].PID, d.Chain[len(d.Chain)-1].PID, d.Chain[1].PID)
	}
}

func TestKillChainArgumentsAreBoundedAndMarked(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, nil, []string{`^victim$`}))
	h.startNginx(master, 8_000_000_000_001)
	sh := key(1400, 9_100_000_000_000)
	huge := strings.Repeat("x", 5000)
	h.handle(forkEv(master, sh, 9_100_000_000_001), execEv(sh, master, 9_100_000_000_002, "dash", "/usr/bin/dash", "sh", "-c", "--", huge))
	victim := key(1500, 9_200_000_000_000)
	h.handle(forkEv(sh, victim, 9_200_000_000_001), execEv(victim, sh, 9_200_000_000_002, "victim", "/usr/bin/victim", "victim"))
	d := h.last().Details.(*event.KillDetails)
	if len(d.Chain) != 2 {
		t.Fatalf("chain %+v", d.Chain)
	}
	l := d.Chain[1]
	if len(l.Argv) != 3 || l.ArgvComplete == nil || *l.ArgvComplete {
		t.Errorf("an argument above the size limit must be left out and the list marked incomplete: %d args, complete %v", len(l.Argv), l.ArgvComplete)
	}
}

func TestKillChainWithoutArgumentCapture(t *testing.T) {
	h := newHarness(t, func(o *Options) {
		o.Kill = rules(t, []string{"image"}, nil, []string{`^victim$`})
		o.CaptureArgv = false
	})
	h.startNginx(master, 8_000_000_000_001)
	victim := key(1500, 9_200_000_000_000)
	h.handle(forkEv(master, victim, 9_200_000_000_001), execEv(victim, master, 9_200_000_000_002, "victim", "/usr/bin/victim"))
	d := h.last().Details.(*event.KillDetails)
	if len(d.Chain) != 1 || d.Chain[0].Argv != nil || d.Chain[0].ArgvComplete != nil {
		t.Errorf("without capture.argv the chain names the executables only: %+v", d.Chain)
	}
}

func TestKillChainSanitizesInvalidUTF8(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, nil, []string{`^victim$`}))
	h.startNginx(master, 8_000_000_000_001)
	sh := key(1400, 9_100_000_000_000)
	h.handle(forkEv(master, sh, 9_100_000_000_001), execEv(sh, master, 9_100_000_000_002, "dash", "/usr/bin/dash", "sh", "-c", "--", "ab\xffcd"))
	victim := key(1500, 9_200_000_000_000)
	h.handle(forkEv(sh, victim, 9_200_000_000_001), execEv(victim, sh, 9_200_000_000_002, "victim", "/usr/bin/victim", "victim"))
	e := h.last()
	if got := e.Details.(*event.KillDetails).Chain[1].Argv[3]; got != "ab�cd" {
		t.Errorf("argv %q", got)
	}
	found := false
	for _, f := range e.DataQuality.SanitizedFields {
		found = found || f == "details.chain"
	}
	if !found {
		t.Errorf("sanitized_fields %v", e.DataQuality.SanitizedFields)
	}
}

var _ = collector.Key{}
