package app

import (
	"os"
	"strconv"
	"time"

	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/output"
	"github.com/Neo23x0/process-watcher/internal/proctree"
)

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }

func (a *App) outputNames() []string {
	names := []string{"file"}
	for name := range a.sink.RemoteStats() {
		names = append(names, name)
	}
	// stable order: file, then tcp, udp, webhook
	order := map[string]int{"file": 0, "tcp": 1, "udp": 2, "webhook": 3}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && order[names[j]] < order[names[j-1]]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}

// emitStarted announces the run before the startup reconciliation is done. It
// makes no claim of completeness: history before the hooks were active is
// unknown.
func (a *App) emitStarted() error {
	info := a.col.Info()
	src := a.src
	if src == "" {
		src = "built-in defaults"
	}
	d := &event.StartedDetails{
		Version:            a.opt.Version,
		PID:                os.Getpid(),
		Kernel:             info.Kernel,
		Arch:               info.Arch,
		Phase:              "initializing",
		CompleteCapture:    false,
		HooksActiveBootNS:  itoa(info.HooksActiveNS),
		HistoryBeforeHooks: "unknown",
		ConfigSource:       src,
		WatchImageContains: append([]string{}, a.cfg.Watch.ImageContains...),
		CaptureArgv:        a.cfg.Capture.Argv,
		Outputs:            a.outputNames(),
		Kill: event.KillStatus{
			Enabled: a.cfg.Kill.Enabled,
			DryRun:  a.cfg.Kill.DryRun,
			Fields:  append([]string{}, a.cfg.Kill.Fields...),
		},
	}
	if a.rules != nil {
		d.Kill.Rules = a.rules.Count()
	}
	if a.repair.Repaired {
		d.LogRepair = &event.LogRepair{Repaired: true, Bytes: a.repair.Bytes, SavedAs: a.repair.SavedAs}
	}
	ev := a.factory.New(event.TypeAgentStarted, event.SourceAgent)
	ev.Details = d
	return a.sink.Emit(ev)
}

// emitReady reports that the hooks are active and the snapshot and the
// buffered records are reconciled.
func (a *App) emitReady(res proctree.SnapshotResult, snap *collector.Snapshot, buffered int) error {
	info := a.col.Info()
	d := &event.ReadyDetails{
		ObservingSinceBootNS: itoa(info.HooksActiveNS),
		SnapshotStartBootNS:  itoa(snap.StartNS),
		SnapshotEndBootNS:    itoa(snap.EndNS),
		SnapshotProcesses:    len(snap.Procs),
		DiscoveredRoots:      res.Roots,
		DiscoveredProcesses:  res.Descendants,
		BufferedRecords:      buffered,
		Note: "Process lifecycles are observed from observing_since_boot_ns on. Earlier history is not available; " +
			"processes that already existed are reported as process.discovered with their current relations.",
	}
	ev := a.factory.New(event.TypeAgentReady, event.SourceAgent)
	ev.Details = d
	return a.sink.Emit(ev)
}

// emitGap reports lost records or another observation gap.
func (a *App) emitGap(cause string, lost event.LostCounts, total uint64, msg, reconcile string) error {
	ev := a.factory.New(event.TypeAgentGap, event.SourceAgent)
	ev.DataQuality.CollectionGap = true
	ev.Details = &event.GapDetails{Cause: cause, Lost: lost, LostTotal: total, Message: msg, Reconcile: reconcile}
	return a.sink.Emit(ev)
}

func (a *App) collectorStats() event.CollectorStats {
	st, err := a.col.Stats()
	if err != nil {
		st = a.lastStats
	}
	return event.CollectorStats{
		Lost:           event.LostCounts{Fork: st.LostFork, Exec: st.LostExec, Exit: st.LostExit},
		LostTotal:      st.Lost(),
		Records:        event.LostCounts{Fork: st.Fork, Exec: st.Exec, Exit: st.Exit},
		ThreadClones:   st.ThreadClones,
		DuplicateExits: st.DuplicateExits,
		PathErrors:     st.PathErrors,
		ArgsErrors:     st.ArgsErrors,
		RingPending:    a.col.Pending(),
		TableFull:      a.engine.Stats().TableFull,
		LiveTableOOR:   st.LiveOutOfRange,
	}
}

func (a *App) outputStats() map[string]event.OutputStats {
	fs := a.file.Stats()
	out := map[string]event.OutputStats{
		"file": {
			Lines: uint64(fs.Lines), Bytes: uint64(fs.Bytes), Rotations: uint64(fs.Rotations),
			Failed: uint64(fs.WriteErrors + fs.SyncErrors),
		},
	}
	for name, rs := range a.sink.RemoteStats() {
		out[name] = event.OutputStats{
			QueueLen:         rs.QueueLen,
			HandedOver:       uint64(rs.HandedOver),
			DroppedQueueFull: uint64(rs.DroppedQueueFull),
			DroppedTooLarge:  uint64(rs.DroppedTooLarge),
			DroppedShutdown:  uint64(rs.DroppedShutdown),
			Failed:           uint64(rs.Failed),
			Retries:          uint64(rs.Retries),
		}
	}
	return out
}

func (a *App) responseStats() *event.ResponseStats {
	if a.worker == nil {
		return nil
	}
	c := a.worker.Counters()
	return &event.ResponseStats{
		RuleHits:         a.engine.Stats().KillHits,
		SignalAttempts:   c.SignalAttempts,
		SignalsAccepted:  c.SignalsAccepted,
		AlreadyExited:    c.AlreadyExited,
		PermissionDenied: c.PermissionDenied,
		Errors:           c.Errors,
		DryRun:           c.DryRun,
		Skipped:          c.Skipped,
		QueueLen:         c.QueueLen,
		QueueCap:         256,
		LatencyCount:     c.LatencyCount,
		LatencyAvgNS:     c.LatencyAvgNS,
		LatencyMaxNS:     c.LatencyMaxNS,
	}
}

func (a *App) filterStats() event.FilterStats {
	_, exR, exA := a.sink.Counts()
	return event.FilterStats{ExcludedRemote: exR, ExcludedAll: exA, DepthSuppress: a.engine.Stats().DepthSuppressed}
}

func (a *App) trackedStats() event.TrackedStats {
	st := a.engine.Stats()
	return event.TrackedStats{
		Roots: st.Roots, Instances: st.Instances, Retained: st.Retained,
		Limit: a.cfg.Runtime.MaxProcesses, GapOpen: st.GapOpen,
	}
}

func (a *App) uptimeNS() string {
	return itoa(uint64(time.Since(a.startedAt)))
}

// emitHealth reports counters of the current run. Delivery counters for TCP
// and UDP mean "handed to the transport", not acknowledged by the receiver.
func (a *App) emitHealth() error {
	byType, _, _ := a.sink.Counts()
	ev := a.factory.New(event.TypeAgentHealth, event.SourceAgent)
	ev.Details = &event.HealthDetails{
		UptimeNS:  a.uptimeNS(),
		Tracked:   a.trackedStats(),
		Collector: a.collectorStats(),
		Events:    byType,
		Filter:    a.filterStats(),
		Outputs:   a.outputStats(),
		Response:  a.responseStats(),
	}
	return a.sink.Emit(ev)
}

func (a *App) stoppedDetails(reason string, runErr error, undelivered map[string]int) *event.StoppedDetails {
	byType, _, _ := a.sink.Counts()
	d := &event.StoppedDetails{
		Reason:       reason,
		UptimeNS:     a.uptimeNS(),
		Collector:    a.collectorStats(),
		Events:       byType,
		Filter:       a.filterStats(),
		Outputs:      a.outputStats(),
		Response:     a.responseStats(),
		UndeliveredN: undelivered,
	}
	if runErr != nil {
		d.Error = event.Str(runErr.Error())
	}
	return d
}

var _ = output.RepairInfo{}
