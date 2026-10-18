package proctree

import (
	"sort"

	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/event"
)

// Discovery modes of ApplySnapshot.
const (
	DiscoveryStartup   = "startup"
	DiscoveryReconcile = "reconcile"
)

// inferGrace: an instance younger than this at the start of a snapshot is not
// declared gone only because the snapshot does not list it.
const inferGrace = 200_000_000 // ns

// SnapshotResult summarises one reconciliation.
type SnapshotResult struct {
	Roots         int // new roots discovered
	Descendants   int // new descendants discovered
	Replayed      int // buffered live records applied afterwards
	InferredExits int // tracked processes found gone without an exit record
}

// ApplySnapshot merges a snapshot of the living processes with the live
// records that were buffered while it was taken.
//
// Live records win: a process whose fork record is among the buffered records
// is not discovered, its whole life is reported from the records. The living
// descendants of observed processes and the living processes that match a
// watch pattern (and are no descendants of one) are discovered; they are
// reported as process.discovered, never as invented forks. The buffered
// records are applied afterwards in ring order; records that are older than
// the snapshot record of the same instance are already reflected by it.
// Finally, tracked processes the snapshot does not show, although they were
// known before it started, are closed as inferred exits.
func (e *Engine) ApplySnapshot(snap *collector.Snapshot, pending []collector.Event, discovery string) (SnapshotResult, error) {
	var res SnapshotResult

	procs := make([]*collector.SnapProc, len(snap.Procs))
	for k := range snap.Procs {
		procs[k] = &snap.Procs[k]
	}
	sort.Slice(procs, func(a, b int) bool {
		if procs[a].Key.StartNS != procs[b].Key.StartNS {
			return procs[a].Key.StartNS < procs[b].Key.StartNS
		}
		return procs[a].Key.TGID < procs[b].Key.TGID
	})
	byKey := make(map[collector.Key]*collector.SnapProc, len(procs))
	children := make(map[collector.Key][]*collector.SnapProc)
	for _, p := range procs {
		byKey[p.Key] = p
		if !p.Parent.IsZero() {
			children[p.Parent] = append(children[p.Parent], p)
		}
	}
	bornLive := make(map[collector.Key]struct{})
	for _, ev := range pending {
		if ev.Kind == collector.KindFork {
			bornLive[ev.Proc] = struct{}{}
		}
	}
	taken := func(p *collector.SnapProc) bool {
		if _, ok := bornLive[p.Key]; ok {
			return true
		}
		return e.inst[p.Key] != nil
	}

	// Roots: matching processes that are no descendant of an observed or of
	// another matching process.
	var frontier []*Instance
	for _, i := range e.sortedInstances() {
		frontier = append(frontier, i)
	}
	for _, p := range procs {
		if taken(p) || !p.ImageOK || !e.o.Matcher.Match(p.Image) || e.hasObservedAncestor(p, byKey) {
			continue
		}
		i, err := e.discover(p, nil, byKey, discovery)
		if err != nil {
			return res, err
		}
		if i != nil {
			res.Roots++
			frontier = append(frontier, i)
		}
	}
	// Breadth first: the living children of every observed process.
	for len(frontier) > 0 {
		x := frontier[0]
		frontier = frontier[1:]
		for _, c := range children[x.Key] {
			if taken(c) {
				continue
			}
			i, err := e.discover(c, x, byKey, discovery)
			if err != nil {
				return res, err
			}
			if i != nil {
				res.Descendants++
				frontier = append(frontier, i)
			}
		}
	}

	for _, ev := range pending {
		if err := e.HandleEvent(ev); err != nil {
			return res, err
		}
		res.Replayed++
	}

	if discovery == DiscoveryReconcile {
		n, err := e.inferExits(snap, byKey)
		if err != nil {
			return res, err
		}
		res.InferredExits = n
	}
	e.gapOpen = false
	return res, nil
}

// hasObservedAncestor walks the snapshot parent chain looking for an observed
// instance or a matching process (which will be admitted itself).
func (e *Engine) hasObservedAncestor(p *collector.SnapProc, byKey map[collector.Key]*collector.SnapProc) bool {
	cur := p
	for n := 0; n < 4096; n++ {
		par, ok := byKey[cur.Parent]
		if !ok {
			return e.inst[cur.Parent] != nil
		}
		if e.inst[par.Key] != nil || (par.ImageOK && e.o.Matcher.Match(par.Image)) {
			return true
		}
		cur = par
	}
	return false
}

// discover admits one living process found by the snapshot.
func (e *Engine) discover(rec *collector.SnapProc, parent *Instance, byKey map[collector.Key]*collector.SnapProc, discovery string) (*Instance, error) {
	if !e.hasRoom() {
		return nil, nil
	}
	i := e.newInstance(rec.Key, rec.VisitNS)
	i.visitNS = rec.VisitNS
	i.Image, i.ImageOK = rec.Image, rec.ImageOK
	i.Path = rec.Path
	i.ImageState = event.StateSnapshot
	i.Comm, i.UID, i.EUID, i.GID = rec.Comm, rec.UID, rec.EUID, rec.GID
	if e.o.CaptureArgv {
		i.ArgsState = event.StateSnapshot
		i.Args = collector.Args{State: collector.ArgsFailed}
		if e.o.SnapshotArgs != nil {
			i.Args = e.o.SnapshotArgs(rec.Key)
		}
	}
	// A reconciliation that follows a loss cannot vouch for relations with
	// observed records.
	i.GapAffected = e.gapOpen

	if parent == nil {
		e.makeRoot(i, rec.Image, rec.ImageOK, rec.Path)
		switch {
		case byKey[rec.Parent] != nil:
			pp := byKey[rec.Parent]
			po := &event.Parent{
				ProcessID:          event.ProcessID(e.bootID(), pp.Key.TGID, pp.Key.StartNS),
				PID:                pp.Key.TGID,
				Image:              optStr(pp.Image, pp.ImageOK),
				RelationshipSource: event.RelSnapshotPPID,
			}
			if pp.Path.Known {
				v, _ := event.Sanitize(pp.Path.Value)
				po.ImagePath = &v
			}
			i.parentOut = po
		case !rec.Parent.IsZero():
			i.parentOut = &event.Parent{
				ProcessID:          event.ProcessID(e.bootID(), rec.Parent.TGID, rec.Parent.StartNS),
				PID:                rec.Parent.TGID,
				RelationshipSource: event.RelSnapshotPPID,
			}
		default:
			i.parentUnknown = true
		}
	} else {
		i.Role = event.RoleDescendant
		i.Depth = parent.Depth + 1
		i.Root = parent.Root
		i.Parent = parent
		parent.refs++
		i.parentOut = e.parentOf(parent, event.RelSnapshotPPID)
		i.GapAffected = i.GapAffected || parent.GapAffected
	}

	pev := e.o.Factory.NewAt(event.TypeProcessDiscovered, event.SourceSnapshot, rec.VisitNS)
	e.fill(pev, i)
	pev.Details = &event.DiscoveredDetails{Discovery: discovery, VisitBootNS: itoa(rec.VisitNS)}
	e.stats.Discovered++
	if err := e.emitProcess(pev, i); err != nil {
		return nil, err
	}
	return i, e.evalKill(i, pev, rec.VisitNS, false)
}

func (e *Engine) sortedInstances() []*Instance {
	out := make([]*Instance, 0, len(e.inst))
	for _, i := range e.inst {
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Key.StartNS != out[b].Key.StartNS {
			return out[a].Key.StartNS < out[b].Key.StartNS
		}
		return out[a].Key.TGID < out[b].Key.TGID
	})
	return out
}

// inferExits closes tracked instances that were known before the snapshot
// started but are not in it. No exit status is invented: the event says that
// the exit itself was not observed.
func (e *Engine) inferExits(snap *collector.Snapshot, byKey map[collector.Key]*collector.SnapProc) (int, error) {
	n := 0
	for _, i := range e.sortedInstances() {
		if _, present := byKey[i.Key]; present {
			continue
		}
		if i.knownSince+inferGrace >= snap.StartNS {
			continue
		}
		pev := e.o.Factory.NewAt(event.TypeProcessExit, event.SourceSnapshot, snap.EndNS)
		e.fill(pev, i)
		pev.DataQuality.CollectionGap = true
		pev.DataQuality.MissingFields = append(pev.DataQuality.MissingFields,
			event.Missing{Field: "details.exit_code", Reason: event.ReasonNotObserved},
			event.Missing{Field: "details.signal", Reason: event.ReasonNotObserved},
			event.Missing{Field: "details.duration_ns", Reason: event.ReasonNotObserved})
		d := &event.ExitDetails{ExitSource: "inferred"}
		if i.ActionID != "" {
			d.ResponseActionID = event.Str(i.ActionID)
		}
		pev.Details = d
		e.stats.InferredExits++
		err := e.emitProcess(pev, i)
		e.retire(i)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
