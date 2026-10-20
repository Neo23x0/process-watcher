package app

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/Neo23x0/process-watcher/internal/config"
	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/output"
)

func consoleLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func requireAll(t *testing.T, what, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("%s: %q is missing in\n%s", what, w, out)
		}
	}
}

func TestKillModeNoticeSaysWhatTheRulesDo(t *testing.T) {
	var buf bytes.Buffer
	killModeNotice(consoleLogger(&buf), config.KillConfig{Enabled: false, DryRun: true})
	if buf.Len() != 0 {
		t.Errorf("disabled kill rules must print nothing, got %q", buf.String())
	}

	buf.Reset()
	killModeNotice(consoleLogger(&buf), config.KillConfig{Enabled: true, DryRun: true, Fields: []string{"image", "argv"}, Regex: []string{"a", "b"}, Strings: []string{"c"}})
	requireAll(t, "dry run", buf.String(), "level=INFO", "dry run", "no signal is sent", "rules=3", "--kill-dry-run=false")

	buf.Reset()
	killModeNotice(consoleLogger(&buf), config.KillConfig{Enabled: true, Strings: []string{"x"}})
	out := buf.String()
	requireAll(t, "live", out, "level=WARN", "SIGKILL", "rules=1")
	if strings.Contains(out, "dry run") {
		t.Errorf("a live run must not read like a dry run: %s", out)
	}
}

func killResult(outcome string, reason *string, rules []event.RuleHit) *event.Event {
	img := "bash"
	return &event.Event{
		EventType: event.TypeKillResult,
		Process:   &event.Process{PID: 4711, Image: &img, Argv: []string{"sh", "-c", "--", "curl https://example.invalid/?token=hunter2"}},
		Details:   &event.KillDetails{Outcome: outcome, Reason: reason, ExecIndex: 1, Rules: rules},
	}
}

func TestKillDecisionNoticeNamesTheTargetAndTheRulesButNoArguments(t *testing.T) {
	idx := 3
	rules := []event.RuleHit{{Ref: "kill.regex[0]", Field: "image"}, {Ref: "kill.regex[5]", Field: "argv", ArgIndex: &idx}}

	var buf bytes.Buffer
	killDecisionNotice(consoleLogger(&buf), killResult(event.OutcomeDryRun, nil, rules))
	out := buf.String()
	requireAll(t, "dry run", out, "level=INFO", `msg="kill decision"`, "outcome=dry_run", "image=bash", "pid=4711", "exec_index=1",
		`rules="kill.regex[0] image, kill.regex[5] argv[3]"`)
	if strings.Contains(out, "hunter2") || strings.Contains(out, "curl") {
		t.Errorf("the console line must not carry arguments (they can hold secrets): %s", out)
	}

	buf.Reset()
	killDecisionNotice(consoleLogger(&buf), killResult(event.OutcomeSignalSent, nil, rules))
	requireAll(t, "signal sent", buf.String(), "level=WARN", "outcome=signal_sent")

	buf.Reset()
	spared := event.SkipRootImageSpared
	killDecisionNotice(consoleLogger(&buf), killResult(event.OutcomeSkipped, &spared, rules))
	requireAll(t, "skipped", buf.String(), "level=INFO", "outcome=skipped", "reason=root_image_spared")

	buf.Reset()
	many := make([]event.RuleHit, 9)
	for i := range many {
		many[i] = event.RuleHit{Ref: "kill.regex[1]", Field: "image"}
	}
	killDecisionNotice(consoleLogger(&buf), killResult(event.OutcomeDryRun, nil, many))
	requireAll(t, "many rules", buf.String(), "+3 more")
}

// memLog is a local log that keeps the lines in memory.
type memLog struct{ lines []string }

func (m *memLog) Write(b []byte) error      { m.lines = append(m.lines, string(b)); return nil }
func (m *memLog) Sync() error               { return nil }
func (m *memLog) Close() error              { return nil }
func (m *memLog) Stats() output.FileStats   { return output.FileStats{} }
func (m *memLog) Repair() output.RepairInfo { return output.RepairInfo{} }

func TestSinkPrintsFinishedKillDecisionsOnTheConsoleOnly(t *testing.T) {
	var console bytes.Buffer
	file := &memLog{}
	s := NewSink(file, nil, config.ScopeRemote)
	s.SetLog(consoleLogger(&console))

	img := "bash"
	for _, ev := range []*event.Event{
		{EventType: event.TypeProcessExec, Process: &event.Process{PID: 1, Image: &img}},
		{EventType: event.TypeKillRequested, Process: &event.Process{PID: 1, Image: &img}, Details: &event.KillDetails{Outcome: event.OutcomePending}},
	} {
		if err := s.Emit(ev); err != nil {
			t.Fatal(err)
		}
	}
	if console.Len() != 0 {
		t.Errorf("only a finished decision is printed, got %q", console.String())
	}

	if err := s.Emit(killResult(event.OutcomeDryRun, nil, nil)); err != nil {
		t.Fatal(err)
	}
	requireAll(t, "result", console.String(), "msg=\"kill decision\"", "outcome=dry_run")
	if len(file.lines) != 3 {
		t.Errorf("the log file gets every event: %d lines, want 3", len(file.lines))
	}

	// Without a console logger the sink works as before.
	quiet := NewSink(&memLog{}, nil, config.ScopeRemote)
	if err := quiet.Emit(killResult(event.OutcomeDryRun, nil, nil)); err != nil {
		t.Fatal(err)
	}
}

func TestEventsPathIsAbsolute(t *testing.T) {
	if got := eventsPath("/var/log/process-watcher/events.jsonl"); got != "/var/log/process-watcher/events.jsonl" {
		t.Errorf("an absolute path stays as it is: %q", got)
	}
	if got := eventsPath("./process-watcher.jsonl"); !strings.HasPrefix(got, "/") || !strings.HasSuffix(got, "/process-watcher.jsonl") {
		t.Errorf("a relative path becomes absolute: %q", got)
	}
}
