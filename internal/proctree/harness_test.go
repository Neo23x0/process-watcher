package proctree

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Neo23x0/process-watcher/internal/clock"
	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/filter"
	"github.com/Neo23x0/process-watcher/internal/response"
	"github.com/Neo23x0/process-watcher/internal/schemacheck"
)

const testBootID = "b53c175a-2d90-4d0c-8c94-dfc2c15eb199"

// recorder is an Emitter that keeps every event.
type recorder struct {
	events []*event.Event
	err    error
}

func (r *recorder) Emit(ev *event.Event) error {
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, ev)
	return nil
}

// ofType returns the recorded events of one type.
func (r *recorder) ofType(typ string) []*event.Event {
	var out []*event.Event
	for _, e := range r.events {
		if e.EventType == typ {
			out = append(out, e)
		}
	}
	return out
}

// describe renders the stream compactly: "process.exec:1235 ...".
func (r *recorder) describe() string {
	var parts []string
	for _, e := range r.events {
		s := e.EventType
		if e.Process != nil {
			s += fmt.Sprintf(":%d", e.Process.PID)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

type skipped struct {
	action *response.Action
	reason string
}

type fakeResponder struct {
	submitted []*response.Action
	skipped   []skipped
}

func (f *fakeResponder) Submit(a *response.Action) { f.submitted = append(f.submitted, a) }
func (f *fakeResponder) Skip(a *response.Action, reason string) {
	f.skipped = append(f.skipped, skipped{a, reason})
}

type harness struct {
	t    *testing.T
	e    *Engine
	rec  *recorder
	resp *fakeResponder
	clk  *clock.Fake
}

// newHarness creates an engine watching "nginx" with a fixed clock: boot time
// 9 000 124 000 000 ns corresponds to 2026-10-17T12:00:00.124Z.
func newHarness(t *testing.T, tweak ...func(*Options)) *harness {
	t.Helper()
	h := &harness{t: t, rec: &recorder{}, resp: &fakeResponder{}}
	h.clk = &clock.Fake{Boot: 9_000_124_000_000, Wall: time.Date(2026, 10, 17, 12, 0, 0, 124_000_000, time.UTC)}
	n := 0
	o := Options{
		Factory: &event.Factory{
			AgentInstanceID: "8f733e92-0ef0-4a3b-829c-0c90e056bdf6",
			Host:            event.Host{Hostname: "web01", BootID: testBootID},
			Clock:           h.clk,
			NewID:           func() string { n++; return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) },
		},
		Emitter:      h.rec,
		Matcher:      filter.NewMatcher([]string{"nginx"}, false),
		MaxProcesses: 1000,
		Responder:    h.resp,
		AgentPID:     4242,
	}
	for _, f := range tweak {
		f(&o)
	}
	h.e = New(o)
	// Every event any test produces must satisfy the published JSON Schema.
	t.Cleanup(func() {
		for i, ev := range h.rec.events {
			ev.Sequence = uint64(i + 1)
			line, err := ev.MarshalLine()
			if err != nil {
				t.Errorf("event %d (%s) does not serialize: %v", i, ev.EventType, err)
				continue
			}
			if err := schemacheck.Validate(line); err != nil {
				t.Errorf("event %d (%s) violates the schema: %v\n%s", i, ev.EventType, err, line)
			}
		}
	})
	return h
}

func key(tgid uint32, start uint64) collector.Key { return collector.Key{TGID: tgid, StartNS: start} }

func forkEv(parent, child collector.Key, bootNS uint64) collector.Event {
	return collector.Event{Kind: collector.KindFork, BootNS: bootNS, Proc: child, Parent: parent, TID: parent.TGID,
		UID: 33, EUID: 33, GID: 33, Comm: "forked"}
}

func execEv(proc, parent collector.Key, bootNS uint64, image, path string, argv ...string) collector.Event {
	return collector.Event{
		Kind: collector.KindExec, BootNS: bootNS, Proc: proc, Parent: parent, TID: proc.TGID,
		UID: 33, EUID: 33, GID: 33, Comm: image,
		Exec: collector.ExecInfo{
			Image: image, ImageOK: true,
			Path:     collector.Path{Value: path, Known: true},
			Filename: path, FilenameOK: true,
			Args: collector.Args{State: collector.ArgsCaptured, List: argv, Argc: len(argv)},
		},
	}
}

func exitEv(proc collector.Key, bootNS uint64, status int32) collector.Event {
	return collector.Event{Kind: collector.KindExit, BootNS: bootNS, Proc: proc, TID: proc.TGID, ExitStatus: status}
}

func (h *harness) handle(evs ...collector.Event) {
	h.t.Helper()
	for _, ev := range evs {
		if err := h.e.HandleEvent(ev); err != nil {
			h.t.Fatalf("HandleEvent(%s %v): %v", ev.Kind, ev.Proc, err)
		}
	}
}

func (h *harness) last() *event.Event {
	h.t.Helper()
	if len(h.rec.events) == 0 {
		h.t.Fatal("no events recorded")
	}
	return h.rec.events[len(h.rec.events)-1]
}

func (h *harness) expect(want string) {
	h.t.Helper()
	if got := h.rec.describe(); got != want {
		h.t.Fatalf("events:\n got  %s\n want %s", got, want)
	}
}

// startNginx runs the exec of an nginx master that becomes a root.
func (h *harness) startNginx(k collector.Key, bootNS uint64) {
	h.t.Helper()
	h.handle(execEv(k, key(1, 1), bootNS, "nginx", "/usr/sbin/nginx", "nginx", "-g", "daemon off;"))
}
