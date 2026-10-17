package response

import (
	"strconv"
	"time"

	"github.com/Neo23x0/process-watcher/internal/event"
)

// Result describes the completion of an action.
type Result struct {
	Outcome string
	Reason  string          // for skipped
	Err     *event.SysError // system error, if any
	// AttemptedAt is the time of the signal attempt, zero if no signal was
	// attempted.
	AttemptedAt   time.Time
	AttemptBootNS uint64
}

// Rules converts the matched rules to their event form.
func ruleHits(a *Action) []event.RuleHit {
	out := make([]event.RuleHit, 0, len(a.Hits))
	for _, h := range a.Hits {
		rh := event.RuleHit{Ref: h.Ref, Type: h.Type, Pattern: h.Pattern, Field: h.Field}
		if h.ArgIndex >= 0 {
			idx := h.ArgIndex
			rh.ArgIndex = &idx
		}
		out = append(out, rh)
	}
	return out
}

// NewKillEvent builds response.kill_requested (outcome pending) or
// response.kill_result. Both carry the same target, parent, root, lineage and
// data quality as copied at decision time, and the shared action_id.
func NewKillEvent(f *event.Factory, a *Action, typ string, r Result) *event.Event {
	ev := f.New(typ, event.SourceAgent)
	ev.Process = a.Process
	ev.Parent = a.Parent
	ev.Root = a.Root
	ev.Lineage = a.Lineage
	ev.DataQuality = a.DataQuality
	ev.DataQuality.MissingFields = append([]event.Missing{}, a.DataQuality.MissingFields...)
	ev.DataQuality.TruncatedFields = append([]string{}, a.DataQuality.TruncatedFields...)
	ev.DataQuality.SanitizedFields = append([]string{}, a.DataQuality.SanitizedFields...)

	d := &event.KillDetails{
		ActionID:          a.ID,
		TriggerEventID:    a.TriggerEventID,
		TriggerType:       a.TriggerType,
		Action:            "kill",
		Signal:            "SIGKILL",
		DryRun:            a.DryRun,
		ExecIndex:         a.ExecIndex,
		Rules:             ruleHits(a),
		Outcome:           r.Outcome,
		Error:             r.Err,
		TriggerBootNS:     strconv.FormatUint(a.TriggerBootNS, 10),
		DecidedAt:         event.Time(a.DecidedAt),
		DecidedBootNS:     strconv.FormatUint(a.DecidedBootNS, 10),
		DecisionLatencyNS: strconv.FormatInt(int64(a.DecidedBootNS)-int64(a.TriggerBootNS), 10),
	}
	if r.Reason != "" {
		d.Reason = event.Str(r.Reason)
	}
	if !r.AttemptedAt.IsZero() {
		t := event.Time(r.AttemptedAt)
		d.SignalAttemptedAt = &t
		d.SignalAttemptBootNS = event.StrNS(r.AttemptBootNS)
		lat := strconv.FormatInt(int64(r.AttemptBootNS)-int64(a.TriggerBootNS), 10)
		d.AttemptLatencyNS = &lat
	}
	ev.Details = d
	return ev
}
