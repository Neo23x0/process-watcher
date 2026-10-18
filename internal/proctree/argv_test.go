package proctree

import (
	"strings"
	"testing"

	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/event"
)

// What the events say about an argument vector that the capture limits cut. The tests run on the kill
// harness, which is also what proves that a cut argument never feeds a rule.

func TestCompleteArgvIsMarkedComplete(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"zzz"}, nil))
	h.startNginx(master, 8_000_000_000_001)
	p := h.rec.events[len(h.rec.events)-1].Process
	if p.ArgvComplete == nil || !*p.ArgvComplete || p.ArgvCapture != nil {
		t.Fatalf("complete: %v capture: %+v", p.ArgvComplete, p.ArgvCapture)
	}
}

func TestIncompleteArgvCarriesTheEvidence(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"zzz"}, nil))
	h.startNginx(master, 8_000_000_000_001)
	ex := execEv(shell, master, 9_000_000_000_002, "dash", "/usr/bin/dash", "sh", "-c", "--")
	ex.Exec.Args = collector.Args{
		State: collector.ArgsCaptured, List: []string{"sh", "-c", "--"}, Truncated: true, Argc: 4,
		TotalBytes: 6000, CapturedBytes: 4096, Limits: collector.DefaultArgLimits(),
		Partial: &collector.PartialArg{Index: 3, Value: "echo " + strings.Repeat("A", 4000)},
	}
	h.handle(forkEv(master, shell, 9_000_000_000_001), ex)

	p := h.last().Process
	if p.ArgvComplete == nil || *p.ArgvComplete {
		t.Fatalf("argv_complete = %v", p.ArgvComplete)
	}
	c := p.ArgvCapture
	if c == nil || c.Argc == nil || *c.Argc != 4 || c.CapturedArgs != 3 || c.TotalBytes == nil || *c.TotalBytes != 6000 ||
		c.CapturedBytes != 4096 || c.LimitArgs != 32 || c.LimitBytes != 4096 {
		t.Fatalf("capture %+v", c)
	}
	if c.Partial == nil || c.Partial.Index != 3 || len(c.Partial.Value) != 4005 || c.Partial.CapturedBytes != 4005 {
		t.Fatalf("partial %+v", c.Partial)
	}
	if got := h.last().DataQuality.TruncatedFields; len(got) != 1 || got[0] != "process.argv" {
		t.Errorf("truncated_fields %v", got)
	}
	// The list stays what it was: only complete arguments.
	if len(p.Argv) != 3 {
		t.Errorf("argv %q", p.Argv)
	}
}

// The partial argument is evidence only. A rule that would match the cut text must not fire.
func TestThePartialArgumentNeverFeedsARule(t *testing.T) {
	h := killHarness(t, rules(t, []string{"argv"}, nil, []string{`^echo A+$`, `AAAA`}))
	h.startNginx(master, 8_000_000_000_001)
	ex := execEv(shell, master, 9_000_000_000_002, "dash", "/usr/bin/dash", "sh", "-c", "--")
	ex.Exec.Args = collector.Args{
		State: collector.ArgsCaptured, List: []string{"sh", "-c", "--"}, Truncated: true, Argc: 4,
		TotalBytes: 6000, CapturedBytes: 4096, Limits: collector.DefaultArgLimits(),
		Partial: &collector.PartialArg{Index: 3, Value: "echo " + strings.Repeat("A", 4000)},
	}
	h.handle(forkEv(master, shell, 9_000_000_000_001), ex)
	if len(h.resp.submitted) != 0 || len(h.rec.ofType(event.TypeKillRequested)) != 0 {
		t.Fatalf("a cut argument must never become a match: %s", h.rec.describe())
	}
}

func TestPartialArgumentIsSanitized(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"zzz"}, nil))
	h.startNginx(master, 8_000_000_000_001)
	ex := execEv(shell, master, 9_000_000_000_002, "dash", "/usr/bin/dash", "sh", "-c")
	ex.Exec.Args = collector.Args{
		State: collector.ArgsCaptured, List: []string{"sh", "-c"}, Truncated: true, Argc: 3,
		CapturedBytes: 12, Limits: collector.DefaultArgLimits(),
		Partial: &collector.PartialArg{Index: 2, Value: "ab\xffcd"},
	}
	h.handle(forkEv(master, shell, 9_000_000_000_001), ex)
	e := h.last()
	if got := e.Process.ArgvCapture.Partial.Value; got != "ab�cd" || e.Process.ArgvCapture.Partial.CapturedBytes != 5 {
		t.Errorf("partial %q (%d bytes)", got, e.Process.ArgvCapture.Partial.CapturedBytes)
	}
	found := false
	for _, f := range e.DataQuality.SanitizedFields {
		if f == "process.argv_capture.partial.value" {
			found = true
		}
	}
	if !found {
		t.Errorf("sanitized_fields %v", e.DataQuality.SanitizedFields)
	}
}
