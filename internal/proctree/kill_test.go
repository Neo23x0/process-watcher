package proctree

import (
	"testing"

	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/config"
	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/filter"
	"github.com/Neo23x0/process-watcher/internal/killrule"
	"github.com/Neo23x0/process-watcher/internal/response"
)

func rules(t *testing.T, fields, strs, regexes []string) *killrule.Rules {
	t.Helper()
	r, err := killrule.Compile(config.KillConfig{Enabled: true, Fields: fields, Strings: strs, Regex: regexes})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// orderResponder records how many events were already emitted when an action
// was submitted: the decision must be written before the attempt.
type orderResponder struct {
	fakeResponder
	rec       *recorder
	eventsAt  []int
	lastTypes []string
}

func (o *orderResponder) Submit(a *response.Action) {
	o.eventsAt = append(o.eventsAt, len(o.rec.events))
	o.lastTypes = append(o.lastTypes, o.rec.events[len(o.rec.events)-1].EventType)
	o.fakeResponder.Submit(a)
}

func killHarness(t *testing.T, r *killrule.Rules, tweak ...func(*Options)) *harness {
	t.Helper()
	return newHarness(t, append([]func(*Options){func(o *Options) {
		o.Kill = r
		o.CaptureArgv = true
	}}, tweak...)...)
}

func TestNoRulesNoActions(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.CaptureArgv = true }) // Kill == nil: feature off
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, shell, 9_000_000_000_001), execEv(shell, master, 9_000_000_000_002, "useradd", "/usr/sbin/useradd"))
	if len(h.resp.submitted)+len(h.resp.skipped) != 0 || len(h.rec.ofType(event.TypeKillRequested)) != 0 {
		t.Fatalf("observation only: %s", h.rec.describe())
	}
}

func TestDescendantHitWritesTheDecisionBeforeTheAttempt(t *testing.T) {
	var or *orderResponder
	h := killHarness(t, rules(t, []string{"image"}, nil, []string{`^(useradd|usermod)$`}), func(o *Options) {
		or = &orderResponder{}
		o.Responder = or
	})
	or.rec = h.rec
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, shell, 9_000_000_000_001), execEv(shell, master, 9_000_000_000_002, "useradd", "/usr/sbin/useradd", "useradd", "bob"))

	if len(or.submitted) != 1 {
		t.Fatalf("submitted %d actions: %s", len(or.submitted), h.rec.describe())
	}
	a := or.submitted[0]
	req := h.last()
	if req.EventType != event.TypeKillRequested || req.Source != event.SourceAgent || req.BootTimeNS != nil {
		t.Fatalf("last event %s source %s", req.EventType, req.Source)
	}
	if or.lastTypes[0] != event.TypeKillRequested {
		t.Errorf("the decision must be emitted before Submit, last event was %s", or.lastTypes[0])
	}
	d := req.Details.(*event.KillDetails)
	trigger := h.rec.ofType(event.TypeProcessExec)[1]
	if d.ActionID != a.ID || d.TriggerEventID != trigger.EventID || d.TriggerType != event.TypeProcessExec ||
		d.Action != "kill" || d.Signal != "SIGKILL" || d.DryRun || d.ExecIndex != 1 || d.Outcome != event.OutcomePending {
		t.Errorf("details %+v", d)
	}
	if len(d.Rules) != 1 || d.Rules[0].Ref != "kill.regex[0]" || d.Rules[0].Type != "regex" || d.Rules[0].Field != "image" ||
		d.Rules[0].Pattern != `^(useradd|usermod)$` || d.Rules[0].ArgIndex != nil {
		t.Errorf("rules %+v", d.Rules)
	}
	if d.TriggerBootNS != "9000000000002" || d.DecidedBootNS != "9000124000000" || d.DecisionLatencyNS != "123999998" {
		t.Errorf("times %s %s %s", d.TriggerBootNS, d.DecidedBootNS, d.DecisionLatencyNS)
	}
	// The audit event describes the target like a process event does.
	if req.Process.PID != 1235 || req.Root.PID != 1200 || req.Lineage.Role != event.RoleDescendant || req.Parent.PID != 1200 {
		t.Errorf("target %+v root %+v", req.Process, req.Root)
	}
	if a.Key != shell || a.ExecIndex != 1 || a.Live == nil || a.Live.ExecIndex.Load() != 1 || !a.Live.Alive.Load() {
		t.Errorf("action %+v", a)
	}
	// The later exit is correlated through the action id, without claiming causality.
	h.handle(exitEv(shell, 9_000_000_900_000, 9))
	exit := h.last().Details.(*event.ExitDetails)
	if exit.ResponseActionID == nil || *exit.ResponseActionID != a.ID || exit.Signal == nil || *exit.Signal != 9 {
		t.Errorf("exit %+v", exit)
	}
	if a.Live.Alive.Load() {
		t.Error("liveness must turn false when the exit is observed")
	}
}

func TestRootsAndStrangersAreNeverTargets(t *testing.T) {
	r := rules(t, []string{"image"}, []string{"nginx", "useradd"}, nil)
	h := killHarness(t, r)
	// The root itself matches the rule: no action.
	h.startNginx(master, 8_000_000_000_001)
	// A stranger starts useradd: not part of any tree.
	h.handle(execEv(key(900, 7_000_000_000_000), key(1, 1), 7_000_000_000_001, "useradd", "/usr/sbin/useradd"))
	// A root that was discovered at startup.
	h.apply(snapshot(10_000_000_000_000, 10_000_000_100_000,
		snapProc(key(2200, 8_500_000_000_000), key(1, 1), 10_000_000_000_001, "nginx", "/usr/sbin/nginx")), nil, DiscoveryStartup)
	if len(h.resp.submitted) != 0 || len(h.rec.ofType(event.TypeKillRequested)) != 0 {
		t.Fatalf("no signal may be requested: %s", h.rec.describe())
	}
}

func TestGrandchildGetsTheSameReactionWithTheOriginalRoot(t *testing.T) {
	h := killHarness(t, rules(t, []string{"argv"}, []string{"useradd"}, nil))
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, helper, 8_100_000_000_001), execEv(helper, master, 8_100_000_000_002, "legitimate-helper", "/opt/h", "h"),
		forkEv(helper, shell, 9_000_000_000_001), execEv(shell, helper, 9_000_000_000_002, "dash", "/usr/bin/dash", "sh", "-c", "useradd bob"))
	if len(h.resp.submitted) != 1 {
		t.Fatalf("%d actions", len(h.resp.submitted))
	}
	a := h.resp.submitted[0]
	if a.Key != shell || a.Root.PID != 1200 || a.Lineage.Depth != 2 || a.Hits[0].Field != "argv" || a.Hits[0].ArgIndex != 2 {
		t.Errorf("action root %+v lineage %+v hits %+v", a.Root, a.Lineage, a.Hits)
	}
	// The helper above it is not a target of that rule.
}

func TestExclusionsAndOutputDepthDoNotShieldATarget(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"useradd"}, nil), func(o *Options) {
		o.MaxDepth = 1
		o.Exclusions = filter.NewExclusions([]string{"useradd"}, nil, false)
	})
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, helper, 8_100_000_000_001), forkEv(helper, shell, 9_000_000_000_001),
		execEv(shell, helper, 9_000_000_000_002, "useradd", "/usr/sbin/useradd")) // depth 2: suppressed from output and excluded
	if len(h.resp.submitted) != 1 {
		t.Fatalf("the action must not depend on exclusions or depth: %s", h.rec.describe())
	}
	req := h.rec.ofType(event.TypeKillRequested)
	if len(req) != 1 || req[0].Filter.Excluded {
		t.Errorf("audit events are not subject to exclusions: %+v", req)
	}
	// The normal process event of the target is not in the output (depth), the audit event is.
	for _, ev := range h.rec.events {
		if ev.EventType == event.TypeProcessExec && ev.Process.PID == 1235 {
			t.Error("the process event at depth 2 must be suppressed")
		}
	}
}

func TestSeveralRulesOneActionPerExecGeneration(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image", "argv"}, []string{"helper"}, []string{`^demo`}))
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, shell, 9_000_000_000_001),
		execEv(shell, master, 9_000_000_000_002, "demo-long-running-helper", "/opt/demo-long-running-helper", "demo-long-running-helper"))
	if len(h.resp.submitted) != 1 {
		t.Fatalf("%d actions", len(h.resp.submitted))
	}
	hits := h.resp.submitted[0].Hits
	refs := map[string]int{}
	for _, hit := range hits {
		refs[hit.Ref+"/"+hit.Field]++
	}
	if len(hits) != 4 || refs["kill.strings[0]/image"] != 1 || refs["kill.strings[0]/argv"] != 1 || refs["kill.regex[0]/image"] != 1 || refs["kill.regex[0]/argv"] != 1 {
		t.Errorf("all hits are reported together: %v", refs)
	}
	// Another exec of the same instance is a new generation and is judged again, once.
	h.handle(execEv(shell, master, 9_000_000_000_003, "demo-long-running-helper", "/opt/x", "demo-long-running-helper"))
	if len(h.resp.submitted) != 2 || h.resp.submitted[1].ExecIndex != 2 {
		t.Errorf("a later exec is evaluated again: %d actions", len(h.resp.submitted))
	}
	// An exec to something harmless is evaluated and produces nothing.
	h.handle(execEv(shell, master, 9_000_000_000_004, "id", "/usr/bin/id", "id"))
	if len(h.resp.submitted) != 2 {
		t.Errorf("no match, no action")
	}
}

func TestRepeatedSnapshotsDoNotRepeatTheAction(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"useradd"}, nil))
	snap := func(start uint64) *collector.Snapshot {
		return snapshot(start, start+100, snapProc(master, key(1, 1), start+1, "nginx", "/usr/sbin/nginx"),
			snapProc(shell, master, start+2, "useradd", "/usr/sbin/useradd"))
	}
	h.apply(snap(10_000_000_000_000), nil, DiscoveryStartup)
	h.apply(snap(11_000_000_000_000), nil, DiscoveryReconcile)
	h.apply(snap(12_000_000_000_000), nil, DiscoveryReconcile)
	if len(h.resp.submitted) != 1 {
		t.Fatalf("%d actions for three snapshots", len(h.resp.submitted))
	}
	if h.resp.submitted[0].TriggerType != event.TypeProcessDiscovered || h.resp.submitted[0].ExecIndex != 0 {
		t.Errorf("a living child found at startup is judged through process.discovered with exec_index 0: %+v", h.resp.submitted[0])
	}
}

func TestForkUsesOnlyTheInheritedImageNeverCachedArguments(t *testing.T) {
	// An argument rule must not fire on arguments merely cached from the parent.
	h := killHarness(t, rules(t, []string{"argv"}, []string{"daemon"}, nil))
	h.startNginx(master, 8_000_000_000_001) // argv: nginx -g "daemon off;"
	h.handle(forkEv(master, shell, 9_000_000_000_001))
	if len(h.resp.submitted) != 0 {
		t.Fatalf("inherited arguments are not evidence about the child")
	}
	// The same rule fires on the child's own exec arguments.
	h.handle(execEv(shell, master, 9_000_000_000_002, "dash", "/usr/bin/dash", "sh", "-c", "daemon"))
	if len(h.resp.submitted) != 1 {
		t.Fatalf("own arguments must fire: %d", len(h.resp.submitted))
	}

	// An image rule does fire at the fork: the inherited image is reliable.
	h2 := killHarness(t, rules(t, []string{"image"}, nil, []string{"^nginx$"}))
	h2.startNginx(master, 8_000_000_000_001)
	h2.handle(forkEv(master, shell, 9_000_000_000_001))
	if len(h2.resp.submitted) != 1 || h2.resp.submitted[0].TriggerType != event.TypeProcessFork || h2.resp.submitted[0].ExecIndex != 0 {
		t.Fatalf("fork before the first exec has exec_index 0: %+v", h2.resp.submitted)
	}
	// The first exec is a new generation (index 1) and is judged separately.
	h2.handle(execEv(shell, master, 9_000_000_000_002, "nginx", "/usr/sbin/nginx"))
	if len(h2.resp.submitted) != 2 || h2.resp.submitted[1].ExecIndex != 1 {
		t.Errorf("exec generation: %d", len(h2.resp.submitted))
	}
}

func TestParentGoneOrExcludedDescendantsAreStillJudged(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"useradd"}, nil), func(o *Options) {
		o.Exclusions = filter.NewExclusions([]string{"legitimate-helper"}, nil, false)
	})
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, helper, 8_100_000_000_001), execEv(helper, master, 8_100_000_000_002, "legitimate-helper", "/opt/h"),
		forkEv(helper, shell, 9_000_000_000_001), exitEv(helper, 9_000_000_100_000, 0), exitEv(master, 9_000_000_200_000, 0))
	h.handle(execEv(shell, key(1, 1), 9_000_000_300_000, "useradd", "/usr/sbin/useradd")) // the real parent is init now
	if len(h.resp.submitted) != 1 || h.resp.submitted[0].Root.PID != 1200 {
		t.Fatalf("an orphan stays in the tree and is judged: %d", len(h.resp.submitted))
	}
}

func TestUnconfirmedLineageIsNeverActedOn(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"useradd"}, nil))
	h.startNginx(master, 8_000_000_000_001)
	// Fork record lost: the exec names a tracked real parent.
	h.handle(execEv(shell, master, 9_000_000_000_002, "useradd", "/usr/sbin/useradd"))
	if len(h.resp.submitted) != 0 || len(h.resp.skipped) != 1 || h.resp.skipped[0].reason != event.SkipLineageUnconfirmed {
		t.Fatalf("submitted %d skipped %+v", len(h.resp.submitted), h.resp.skipped)
	}
	if len(h.rec.ofType(event.TypeKillRequested)) != 0 {
		t.Error("no pending request may be written for an action that is not taken")
	}
	// Same after a loss when a reconciliation discovers a process.
	h2 := killHarness(t, rules(t, []string{"image"}, []string{"useradd"}, nil))
	h2.startNginx(master, 8_000_000_000_001)
	h2.e.MarkGap()
	h2.apply(snapshot(20_000_000_000_000, 20_000_000_100_000, snapProc(master, key(1, 1), 20_000_000_000_001, "nginx", "/usr/sbin/nginx"),
		snapProc(shell, master, 20_000_000_000_002, "useradd", "/usr/sbin/useradd")), nil, DiscoveryReconcile)
	if len(h2.resp.submitted) != 0 || len(h2.resp.skipped) != 1 {
		t.Fatalf("after a loss: submitted %d skipped %d", len(h2.resp.submitted), len(h2.resp.skipped))
	}
}

func TestAgentAndInitAreNotEligible(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"x"}, nil)) // matches every test image below
	h.startNginx(master, 8_000_000_000_001)
	agent := key(4242, 9_000_000_000_000) // Options.AgentPID in the harness
	h.handle(forkEv(master, agent, 9_000_000_000_001), execEv(agent, master, 9_000_000_000_002, "x-agent", "/usr/bin/x-agent"))
	init1 := key(1, 5_000_000_000)
	h.handle(forkEv(master, init1, 9_000_000_000_011), execEv(init1, master, 9_000_000_000_012, "x-init", "/sbin/x-init"))
	if len(h.resp.submitted) != 0 {
		t.Fatalf("the agent and pid 1 are no targets, got %d actions", len(h.resp.submitted))
	}
	if h.e.Stats().KillIneligible == 0 {
		t.Error("ineligible hits are counted")
	}
}

func TestIncompleteValuesNeverFeedARule(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image", "image_path", "argv"}, nil, []string{`^useradd$`, `^/usr/sbin/useradd$`}))
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, shell, 9_000_000_000_001))
	// The kernel could only copy the beginning of the arguments, the path and the image name:
	// "^useradd$" would match the cut values, but cut values are no evidence.
	ex := execEv(shell, master, 9_000_000_000_002, "useradd", "/usr/sbin/useradd", "useradd")
	ex.Exec.ImageTruncated = true
	ex.Exec.Path.Truncated = true
	ex.Exec.Args = collector.Args{State: collector.ArgsCaptured, List: []string{"/usr/bin/true"}, Truncated: true, Argc: 3}
	h.handle(ex)
	if len(h.resp.submitted) != 0 {
		t.Fatalf("a truncated value must not produce a hit: %+v", h.resp.submitted[0].Hits)
	}
	// The same program with complete values is a hit; the complete prefix of a cut vector still counts.
	other := key(1236, 9_000_000_100_000)
	h.handle(forkEv(master, other, 9_000_000_100_001))
	ex2 := execEv(other, master, 9_000_000_100_002, "useradd", "/usr/sbin/useradd", "useradd", "bob")
	ex2.Exec.Args.Truncated = true // more arguments existed, the captured ones are complete
	h.handle(ex2)
	if len(h.resp.submitted) != 1 || len(h.resp.submitted[0].Hits) != 3 {
		t.Fatalf("complete values must hit: %+v", h.resp.submitted)
	}
	// A capture failure means no argument evidence, other fields still work.
	third := key(1237, 9_000_000_200_000)
	h.handle(forkEv(master, third, 9_000_000_200_001))
	ex3 := execEv(third, master, 9_000_000_200_002, "useradd", "/usr/sbin/useradd")
	ex3.Exec.Args = collector.Args{State: collector.ArgsFailed}
	h.handle(ex3)
	if len(h.resp.submitted) != 2 {
		t.Errorf("image and path still match without argv: %d", len(h.resp.submitted))
	}
}

func TestDryRunIsMarkedAndExitsDoNotTrigger(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"useradd"}, nil), func(o *Options) { o.DryRun = true })
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, shell, 9_000_000_000_001), execEv(shell, master, 9_000_000_000_002, "useradd", "/usr/sbin/useradd"))
	if len(h.resp.submitted) != 1 || !h.resp.submitted[0].DryRun {
		t.Fatalf("%+v", h.resp.submitted)
	}
	if !h.rec.ofType(event.TypeKillRequested)[0].Details.(*event.KillDetails).DryRun {
		t.Error("the audit event says dry_run")
	}
	n := len(h.resp.submitted)
	h.handle(exitEv(shell, 9_100_000_000_000, 0))
	if len(h.resp.submitted) != n {
		t.Error("process.exit never triggers an action")
	}
}

func TestFailedLocalWriteStopsBeforeSubmitting(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"useradd"}, nil))
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, shell, 9_000_000_000_001))
	h.rec.err = errTest
	if err := h.e.HandleEvent(execEv(shell, master, 9_000_000_000_002, "useradd", "/usr/sbin/useradd")); err == nil {
		t.Fatal("expected the write error")
	}
	if len(h.resp.submitted) != 0 {
		t.Error("no further action may be started after a local write error")
	}
}

func TestNoDecisionsAfterDisableKill(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, []string{"useradd"}, nil))
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, shell, 9_000_000_000_001))
	h.e.DisableKill() // shutdown: nothing new may start
	h.handle(execEv(shell, master, 9_000_000_000_002, "useradd", "/usr/sbin/useradd"))
	if len(h.resp.submitted)+len(h.resp.skipped) != 0 || len(h.rec.ofType(event.TypeKillRequested)) != 0 {
		t.Fatalf("a decision was created during shutdown: %s", h.rec.describe())
	}
	// The observation itself goes on: the exec is still reported.
	if last := h.last(); last.EventType != event.TypeProcessExec {
		t.Errorf("last event %s", last.EventType)
	}
}
