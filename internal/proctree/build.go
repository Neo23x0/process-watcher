package proctree

import (
	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/event"
)

// fill sets the target, parent, root, lineage and gap marker of a process
// event from the current state of i.
func (e *Engine) fill(ev *event.Event, i *Instance) {
	ev.Process = e.processOf(i, &ev.DataQuality)
	ev.Parent = i.parentOut
	ev.Root = i.Root.rootOut
	lin := e.lineageOf(i)
	ev.Lineage = &lin
	ev.DataQuality.CollectionGap = i.GapAffected
}

// emitProcess applies the output depth limit and the exclusions to a process
// event and hands it to the emitter. Neither affects the tracking.
func (e *Engine) emitProcess(ev *event.Event, i *Instance) error {
	if e.o.MaxDepth > 0 && i.Depth > e.o.MaxDepth {
		e.stats.DepthSuppressed++
		return nil
	}
	image := ""
	if i.ImageOK {
		image = i.Image
	}
	for _, m := range e.o.Exclusions.Eval(image, i.Args) {
		fm := event.FilterMatch{Field: m.Field, Value: m.Value}
		if m.Index >= 0 {
			idx := m.Index
			fm.Index = &idx
		}
		ev.Filter.Matches = append(ev.Filter.Matches, fm)
	}
	ev.Filter.Excluded = len(ev.Filter.Matches) > 0
	return e.o.Emitter.Emit(ev)
}

func addUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func (e *Engine) processOf(i *Instance, dq *event.DataQuality) *event.Process {
	san := func(field, v string) string {
		out, changed := event.Sanitize(v)
		if changed {
			dq.SanitizedFields = addUnique(dq.SanitizedFields, field)
		}
		return out
	}
	missing := func(field, reason string) {
		dq.MissingFields = append(dq.MissingFields, event.Missing{Field: field, Reason: reason})
	}

	p := &event.Process{
		ProcessID:   i.ID,
		PID:         i.Key.TGID,
		StartBootNS: itoa(i.Key.StartNS),
		ImageState:  i.ImageState,
		UID:         i.UID,
		EUID:        i.EUID,
		GID:         i.GID,
	}
	if i.ImageOK {
		v := san("process.image", i.Image)
		p.Image = &v
		if i.ImageTruncated {
			dq.TruncatedFields = addUnique(dq.TruncatedFields, "process.image")
		}
	} else {
		missing("process.image", event.ReasonKernelUnavailable)
	}
	if i.Path.Known {
		v := san("process.image_path", i.Path.Value)
		p.ImagePath = &v
		if i.Path.Deleted {
			t := true
			p.ImageDeleted = &t
		}
		if i.Path.Truncated {
			dq.TruncatedFields = addUnique(dq.TruncatedFields, "process.image_path")
		}
	} else {
		missing("process.image_path", event.ReasonKernelUnavailable)
	}
	comm := san("process.comm", i.Comm)
	p.Comm = &comm

	if e.o.CaptureArgv {
		switch i.Args.State {
		case collector.ArgsCaptured:
			list := make([]string, len(i.Args.List))
			for k, a := range i.Args.List {
				list[k] = san("process.argv", a)
			}
			p.Argv = list
			st := i.ArgsState
			p.ArgvState = &st
			if i.Args.Truncated {
				dq.TruncatedFields = addUnique(dq.TruncatedFields, "process.argv")
			}
		case collector.ArgsFailed:
			reason := event.ReasonKernelUnavailable
			if i.ArgsState == event.StateSnapshot {
				reason = event.ReasonProcUnavailable
			}
			missing("process.argv", reason)
		default:
			missing("process.argv", event.ReasonNotCaptured)
		}
	}
	return p
}

// parentOf takes the metadata excerpt of the creating process that is stored
// with the relation.
func (e *Engine) parentOf(p *Instance, source string) *event.Parent {
	po := &event.Parent{ProcessID: p.ID, PID: p.Key.TGID, RelationshipSource: source}
	if p.ImageOK {
		v, _ := event.Sanitize(p.Image)
		po.Image = &v
	}
	if p.Path.Known {
		v, _ := event.Sanitize(p.Path.Value)
		po.ImagePath = &v
	}
	return po
}

// lineageOf lists the ancestors from the root to the direct parent. The
// serialized list is bounded; the real depth is not, and neither is the
// internal tracking.
func (e *Engine) lineageOf(i *Instance) event.Lineage {
	lin := event.Lineage{
		Role:      i.Role,
		Depth:     i.Depth,
		Ancestors: []string{},
		Complete:  i.complete(),
	}
	if i.Depth == 0 {
		return lin
	}
	limit := event.MaxAncestors
	near := i.Depth // ancestors between the root and i, plus the root itself
	if near > limit {
		near = limit - 1 // the root takes the remaining slot
		lin.AncestorsTruncated = true
	}
	chain := make([]string, 0, near)
	for p, n := i.Parent, 0; p != nil && n < near; p, n = p.Parent, n+1 {
		chain = append(chain, p.ID)
	}
	// chain is nearest first; the list is root first.
	for l, r := 0, len(chain)-1; l < r; l, r = l+1, r-1 {
		chain[l], chain[r] = chain[r], chain[l]
	}
	if lin.AncestorsTruncated {
		chain = append([]string{i.Root.ID}, chain...)
	}
	lin.Ancestors = chain
	return lin
}
