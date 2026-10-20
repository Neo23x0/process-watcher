package app

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/Neo23x0/process-watcher/internal/config"
	"github.com/Neo23x0/process-watcher/internal/event"
)

// The events go to the log file only. The notices below tell the operator on
// the console what the kill rules do: without them a dry run is silent, and a
// live run cannot be told from one.

// eventsPath is the local log as an absolute path, for the console.
func eventsPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// killModeNotice logs once, at start, what the kill rules will do.
func killModeNotice(log *slog.Logger, k config.KillConfig) {
	if !k.Enabled {
		return
	}
	rules := len(k.Strings) + len(k.Regex)
	if k.DryRun {
		log.Info("kill rules in dry run: matches are logged, no signal is sent",
			"rules", rules, "fields", k.Fields, "terminate", "set kill.dry_run: false or pass --kill-dry-run=false")
		return
	}
	log.Warn("kill rules are live: matching descendants of the watched processes receive SIGKILL",
		"rules", rules, "fields", k.Fields)
}

// killDecisionNotice logs one line for a finished kill decision, dry run or
// not. It carries no arguments (they can hold secrets); the log file has the
// whole event.
func killDecisionNotice(log *slog.Logger, ev *event.Event) {
	d, ok := ev.Details.(*event.KillDetails)
	if !ok || ev.EventType != event.TypeKillResult {
		return
	}
	attrs := []any{"outcome", d.Outcome}
	if d.Reason != nil {
		attrs = append(attrs, "reason", *d.Reason)
	}
	if p := ev.Process; p != nil {
		if p.Image != nil {
			attrs = append(attrs, "image", *p.Image)
		}
		attrs = append(attrs, "pid", p.PID)
	}
	attrs = append(attrs, "exec_index", d.ExecIndex, "rules", ruleList(d.Rules))
	level := slog.LevelInfo
	switch d.Outcome {
	case event.OutcomeSignalSent, event.OutcomePermissionDenied, event.OutcomeError:
		level = slog.LevelWarn
	}
	log.Log(context.Background(), level, "kill decision", attrs...)
}

// ruleList names the matching rules, for example "kill.regex[5] argv[3]", at
// most six of them.
func ruleList(hits []event.RuleHit) string {
	const most = 6
	var parts []string
	for i, h := range hits {
		if i == most {
			parts = append(parts, fmt.Sprintf("+%d more", len(hits)-most))
			break
		}
		s := h.Ref + " " + h.Field
		if h.ArgIndex != nil {
			s += fmt.Sprintf("[%d]", *h.ArgIndex)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}
