package proctree

import (
	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/killrule"
	"github.com/Neo23x0/process-watcher/internal/response"
)

// killSubject collects the values of i that are proven complete and current.
// For a fresh fork only the inherited image and path qualify: arguments cached
// from the parent are not evidence about the child.
func killSubject(i *Instance, fork bool) killrule.Subject {
	var s killrule.Subject
	if i.ImageOK && !i.ImageTruncated && i.Image != "" {
		v := i.Image
		s.Image = &v
	}
	if i.Path.Known && !i.Path.Truncated && i.Path.Value != "" {
		v := i.Path.Value
		s.ImagePath = &v
	}
	if !fork && i.ArgsState != event.StateInherited && i.Args.State == collector.ArgsCaptured {
		s.Argv = i.Args.List // only complete arguments are in the list
	}
	return s
}

// evalKill applies the kill rules to a confirmed descendant right after the
// event that made new information about it available. The trigger event is
// the process event just built (it may still be suppressed from the output by
// exclusions or the depth limit; the rules do not care).
func (e *Engine) evalKill(i *Instance, trigger *event.Event, triggerBootNS uint64, fork bool) error {
	if e.o.Kill == nil || e.killDisabled || i.Role != event.RoleDescendant {
		return nil
	}
	if i.Key.TGID <= 1 || i.Key.TGID == e.o.AgentPID {
		e.stats.KillIneligible++
		return nil
	}
	if i.killDoneExec >= i.ExecIndex {
		return nil // one decision per (instance, exec index)
	}
	hits := e.o.Kill.Match(killSubject(i, fork))
	if len(hits) == 0 {
		return nil
	}
	i.killDoneExec = i.ExecIndex
	e.stats.KillHits++

	clock := e.o.Factory.Clock
	a := &response.Action{
		ID:             event.NewUUID(),
		TriggerEventID: trigger.EventID,
		TriggerType:    trigger.EventType,
		TriggerBootNS:  triggerBootNS,
		DecidedAt:      clock.Now().UTC(),
		DecidedBootNS:  clock.BootNS(),
		DryRun:         e.o.DryRun,
		Key:            i.Key,
		ExecIndex:      i.ExecIndex,
		Hits:           hits,
		Live:           &i.live,
		Process:        trigger.Process,
		Parent:         trigger.Parent,
		Root:           trigger.Root,
		Lineage:        trigger.Lineage,
		DataQuality:    trigger.DataQuality,
	}
	if i.GapAffected {
		// The tree membership is not backed by observed records: no action on
		// suspicion.
		e.o.Responder.Skip(a, event.SkipLineageUnconfirmed)
		return nil
	}
	// The decision is written locally before any signal attempt.
	req := response.NewKillEvent(e.o.Factory, a, event.TypeKillRequested, response.Result{Outcome: event.OutcomePending})
	a.RequestedEventID = req.EventID
	if err := e.o.Emitter.Emit(req); err != nil {
		return err
	}
	i.ActionID = a.ID
	e.o.Responder.Submit(a)
	return nil
}
