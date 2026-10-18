package proctree

import (
	"slices"

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

const (
	// chainMaxLinks bounds the ancestors listed in an audit event: the root and the
	// nearest ones.
	chainMaxLinks = 8
	// chainArgvBytes bounds the arguments listed per ancestor (the sum of the
	// argument lengths and one separator each).
	chainArgvBytes = 2048
)

// chainOf describes the ancestors of i, root first, for the audit of a decision.
// The second result says that ancestors between the root and the nearest ones were
// left out; the third that invalid UTF-8 was replaced.
func (e *Engine) chainOf(i *Instance) (links []event.ChainLink, truncated, sanitized bool) {
	var anc []*Instance
	for p := i.Parent; p != nil; p = p.Parent {
		anc = append(anc, p)
	}
	slices.Reverse(anc)
	if len(anc) > chainMaxLinks {
		anc = append([]*Instance{anc[0]}, anc[len(anc)-(chainMaxLinks-1):]...)
		truncated = true
	}
	san := func(v string) string {
		out, changed := event.Sanitize(v)
		if changed {
			sanitized = true
		}
		return out
	}
	links = make([]event.ChainLink, 0, len(anc))
	for _, p := range anc {
		l := event.ChainLink{ProcessID: p.ID, PID: p.Key.TGID, ExecIndex: p.ExecIndex}
		if p.ImageOK {
			v := san(p.Image)
			l.Image = &v
		}
		if p.Path.Known && p.Path.Value != "" {
			v := san(p.Path.Value)
			l.ImagePath = &v
		}
		if e.o.CaptureArgv && p.Args.State == collector.ArgsCaptured {
			list, used, cut := make([]string, 0, len(p.Args.List)), 0, false
			for _, a := range p.Args.List {
				if used+len(a)+1 > chainArgvBytes {
					cut = true
					break
				}
				list = append(list, san(a))
				used += len(a) + 1
			}
			complete := !cut && !p.Args.Truncated
			l.Argv, l.ArgvComplete = list, &complete
		}
		links = append(links, l)
	}
	return links, truncated, sanitized
}

// runsRootExecutable reports whether i is running the executable its root had
// when it was admitted. Paths are compared when both are known; otherwise the
// image names are.
func (e *Engine) runsRootExecutable(i *Instance) bool {
	r := i.Root
	if r == nil || r == i {
		return false
	}
	if r.admitPath != nil && i.Path.Known && !i.Path.Truncated && i.Path.Value != "" {
		return *r.admitPath == i.Path.Value
	}
	if r.admitImage != nil && i.ImageOK && !i.ImageTruncated && i.Image != "" {
		img, _ := event.Sanitize(i.Image)
		return *r.admitImage == img
	}
	return false
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
	chain, chainTruncated, chainSanitized := e.chainOf(i)
	dq := trigger.DataQuality
	if chainSanitized {
		dq.SanitizedFields = append(append([]string{}, dq.SanitizedFields...), "details.chain")
	}
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
		DataQuality:    dq,
		Chain:          chain,
		ChainTruncated: chainTruncated,
	}
	if i.GapAffected {
		// The tree membership is not backed by observed records: no action on
		// suspicion.
		e.o.Responder.Skip(a, event.SkipLineageUnconfirmed)
		return nil
	}
	if e.o.KillSpareRootImage && e.runsRootExecutable(i) {
		// A service master forks workers with its own image and re-executes itself
		// on a reload: a rule that matches that image must not take the service down.
		// The decision is audited, so the rule's reach stays visible.
		e.stats.KillSpared++
		e.o.Responder.Skip(a, event.SkipRootImageSpared)
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
