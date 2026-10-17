package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"
	"time"

	"github.com/Neo23x0/process-watcher/internal/clock"
	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/collector/ebpf"
	"github.com/Neo23x0/process-watcher/internal/config"
	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/filter"
	"github.com/Neo23x0/process-watcher/internal/killrule"
	"github.com/Neo23x0/process-watcher/internal/output"
	"github.com/Neo23x0/process-watcher/internal/procfs"
	"github.com/Neo23x0/process-watcher/internal/proctree"
	"github.com/Neo23x0/process-watcher/internal/response"
)

// Exit codes of the agent.
const (
	ExitOK       = 0
	ExitRuntime  = 1 // runtime error, including a failing mandatory log
	ExitConfig   = 2 // invalid configuration or usage
	ExitPlatform = 3 // unsupported platform or missing collector prerequisites
)

// Timings of the run loop that are not configurable (variables so tests can
// shorten them).
var (
	statsInterval      = time.Second
	lossReconcileGap   = time.Second // minimum distance between loss triggered reconciliations
	readDeadline       = 50 * time.Millisecond
	shutdownDrainLimit = 2 * time.Second
)

const (
	housekeepingEvery = 256 // records between two housekeeping passes
	maxDrain          = 1 << 20
	// maxStatsFailures is how many consecutive reads of the kernel loss
	// counters may fail before the agent gives up: without them it would
	// continue without noticing record loss.
	maxStatsFailures = 10
)

// Options are the injectable parts of the agent; the zero value is the real
// system.
type Options struct {
	Version       string
	Stderr        io.Writer
	Getenv        func(string) string
	OpenCollector func(collector.Options) (collector.Collector, error)
	// Preflight checks the prerequisites before anything is created; it
	// defaults to ebpf.Preflight and may be replaced in tests.
	Preflight    func() error
	BootID       func() (string, error)
	Clock        clock.Clock
	System       response.System
	CheckPidfd   func() error
	SnapshotArgs func(collector.Key) collector.Args
	// Hostname defaults to os.Hostname.
	Hostname func() (string, error)
	// OpenLog opens the local log; defaults to output.OpenFile. Tests replace
	// it to inject failures.
	OpenLog func(output.FileOptions) (logFile, error)
}

func (o *Options) defaults() {
	if o.Version == "" {
		o.Version = "dev"
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.OpenCollector == nil {
		o.OpenCollector = ebpf.Open
		if o.Preflight == nil {
			o.Preflight = ebpf.Preflight
		}
	}
	if o.BootID == nil {
		o.BootID = procfs.BootID
	}
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.System == nil {
		o.System = response.NewSystem()
	}
	if o.CheckPidfd == nil {
		o.CheckPidfd = response.CheckSupport
	}
	if o.SnapshotArgs == nil {
		o.SnapshotArgs = procfs.ReadArgs
	}
	if o.Hostname == nil {
		o.Hostname = os.Hostname
	}
	if o.OpenLog == nil {
		o.OpenLog = func(fo output.FileOptions) (logFile, error) { return output.OpenFile(fo) }
	}
}

// App is one agent run.
type App struct {
	cfg  config.Config
	src  string
	opt  Options
	log  *slog.Logger
	runI string // agent_instance_id

	factory *event.Factory
	sink    *Sink
	file    logFile
	col     collector.Collector
	engine  *proctree.Engine
	worker  *response.Worker
	rules   *killrule.Rules

	startedAt time.Time
	startBoot uint64
	repair    output.RepairInfo

	fatal chan error

	lastStats     collector.Stats
	lastLost      uint64
	statsFailures int       // consecutive failed reads of the kernel counters
	reconcileAt   time.Time // when a loss triggered reconciliation is due
	lastReconcile time.Time
	nextStats     time.Time
	nextHealth    time.Time
	nextReconcile time.Time
}

// Run starts the agent and blocks until ctx is cancelled or a fatal error
// occurs. It returns the process exit code.
func Run(ctx context.Context, r *config.Resolved, opt Options) int {
	opt.defaults()
	log := slog.New(slog.NewTextHandler(opt.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	a := &App{cfg: r.Config, src: r.SourceFile, opt: opt, log: log, runI: event.NewUUID(), fatal: make(chan error, 4)}
	code, err := a.run(ctx)
	if err != nil {
		log.Error("process-watcher stopped", "error", err)
	}
	return code
}

func (a *App) run(ctx context.Context) (code int, err error) {
	cfg := a.cfg
	if a.opt.Preflight != nil {
		if err := a.opt.Preflight(); err != nil {
			return ExitPlatform, err
		}
	}
	if cfg.Kill.Enabled {
		if err := a.opt.CheckPidfd(); err != nil {
			return ExitPlatform, fmt.Errorf("kill.enabled needs working pidfd system calls: %w", err)
		}
		rules, err := killrule.Compile(cfg.Kill)
		if err != nil {
			return ExitConfig, err
		}
		a.rules = rules
	}
	token, err := config.ResolveWebhookToken(cfg, a.opt.Getenv)
	if err != nil {
		return ExitConfig, err
	}
	bootID, err := a.opt.BootID()
	if err != nil {
		return ExitRuntime, err
	}
	host, err := a.opt.Hostname()
	if err != nil {
		return ExitRuntime, fmt.Errorf("hostname: %w", err)
	}

	// The remote outputs are built first: everything they reject is a
	// configuration error that must not leave a log directory, an empty log or a
	// lock file behind.
	remotes, err := a.openRemotes(token)
	if err != nil {
		return ExitConfig, err
	}

	file, err := a.opt.OpenLog(output.FileOptions{
		Path:            cfg.Outputs.File.Path,
		RotateSizeBytes: int64(cfg.Outputs.File.RotateSizeMB) << 20,
		KeepFiles:       cfg.Outputs.File.KeepFiles,
		SyncInterval:    cfg.Outputs.File.SyncInterval,
		Logger:          a.log,
		OnFatal:         func(err error) { a.raise(fmt.Errorf("local log fsync: %w", err)) },
	})
	if err != nil {
		shutdownRemotes(remotes)
		return ExitRuntime, fmt.Errorf("open local log: %w", err)
	}
	a.file = file
	a.repair = file.Repair()
	logClosed := false
	closeLog := func() error {
		if logClosed {
			return nil
		}
		logClosed = true
		return file.Close()
	}
	defer closeLog()

	col, err := a.opt.OpenCollector(collector.Options{
		RingBufferBytes: cfg.Runtime.RingBufferMB << 20,
		CaptureArgs:     cfg.Capture.Argv,
		LiveTable:       cfg.Kill.Enabled,
	})
	if err != nil {
		cctx, cancel := context.WithTimeout(context.Background(), time.Second)
		NewSink(file, remotes, cfg.Exclude.Scope).CloseRemotes(cctx)
		cancel()
		var pe *collector.PrerequisiteError
		if errors.As(err, &pe) {
			return ExitPlatform, err
		}
		return ExitRuntime, fmt.Errorf("start collector: %w", err)
	}
	a.col = col
	defer col.Close()

	a.sink = NewSink(file, remotes, cfg.Exclude.Scope)
	a.factory = &event.Factory{
		AgentInstanceID: a.runI,
		Host:            event.Host{Hostname: host, BootID: bootID},
		Clock:           a.opt.Clock,
	}
	a.startedAt = time.Now()
	a.startBoot = a.opt.Clock.BootNS()

	var responder response.Responder
	if cfg.Kill.Enabled {
		a.worker = response.NewWorker(response.Options{
			Factory:  a.factory,
			Emitter:  a.sink,
			Rules:    a.rules,
			System:   a.opt.System,
			Identity: col,
			DryRun:   cfg.Kill.DryRun,
			OnFatal:  func(err error) { a.raise(fmt.Errorf("audit log write: %w", err)) },
		})
		a.worker.Start()
		responder = a.worker
	}
	a.engine = proctree.New(proctree.Options{
		Factory:      a.factory,
		Emitter:      a.sink,
		Matcher:      filter.NewMatcher(cfg.Watch.ImageContains, cfg.Watch.IgnoreCase),
		Exclusions:   filter.NewExclusions(cfg.Exclude.ImageContains, cfg.Exclude.ArgvContains, cfg.Watch.IgnoreCase),
		MaxDepth:     cfg.Watch.MaxDepth,
		MaxProcesses: cfg.Runtime.MaxProcesses,
		CaptureArgv:  cfg.Capture.Argv,
		Kill:         a.rules,
		DryRun:       cfg.Kill.DryRun,
		Responder:    responder,
		AgentPID:     uint32(os.Getpid()),
		SnapshotArgs: a.opt.SnapshotArgs,
	})

	reason, runErr := a.operate(ctx)
	shutdownErr := a.shutdown(reason, runErr)
	if cerr := closeLog(); cerr != nil {
		a.log.Error("closing the local log failed", "error", cerr)
		shutdownErr = errors.Join(shutdownErr, fmt.Errorf("close local log: %w", cerr))
	}
	// The local log is mandatory: a failure while finishing it is a failure of
	// the run even when the run itself ended by a signal.
	if runErr == nil {
		runErr = shutdownErr
	}
	if runErr != nil {
		return ExitRuntime, runErr
	}
	return ExitOK, nil
}

func (a *App) openRemotes(token string) ([]output.Remote, error) {
	cfg := a.cfg
	d := cfg.Delivery
	var remotes []output.Remote
	closeAll := func() { shutdownRemotes(remotes) }
	if cfg.Outputs.TCP.Address != "" {
		r, err := output.NewTCP(output.TCPOptions{
			Address: cfg.Outputs.TCP.Address, TLS: cfg.Outputs.TCP.TLS, CAFile: cfg.Outputs.TCP.CAFile,
			ServerName: cfg.Outputs.TCP.ServerName, QueueSize: d.QueueSize, MaxRetries: d.MaxRetries,
			ConnectTimeout: d.ConnectTimeout, WriteTimeout: d.WriteTimeout, Logger: a.log,
		})
		if err != nil {
			closeAll()
			return nil, err
		}
		remotes = append(remotes, r)
	}
	if cfg.Outputs.UDP.Address != "" {
		r, err := output.NewUDP(output.UDPOptions{
			Address: cfg.Outputs.UDP.Address, MaxBytes: cfg.Outputs.UDP.MaxBytes, QueueSize: d.QueueSize,
			ConnectTimeout: d.ConnectTimeout, WriteTimeout: d.WriteTimeout, Logger: a.log,
		})
		if err != nil {
			closeAll()
			return nil, err
		}
		remotes = append(remotes, r)
	}
	if cfg.Outputs.Webhook.URL != "" {
		r, err := output.NewWebhook(output.WebhookOptions{
			URL: cfg.Outputs.Webhook.URL, Token: token, UserAgentVersion: a.opt.Version,
			QueueSize: d.QueueSize, MaxRetries: d.MaxRetries, ConnectTimeout: d.ConnectTimeout,
			WriteTimeout: d.WriteTimeout, Timeout: cfg.Outputs.Webhook.Timeout, Logger: a.log,
		})
		if err != nil {
			closeAll()
			return nil, err
		}
		remotes = append(remotes, r)
	}
	return remotes, nil
}

// shutdownRemotes stops remote outputs that never received an event.
func shutdownRemotes(remotes []output.Remote) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, r := range remotes {
		r.Shutdown(ctx)
	}
}

// raise reports a fatal error from a background goroutine.
func (a *App) raise(err error) {
	select {
	case a.fatal <- err:
	default:
	}
}

// operate runs the startup sequence and the main loop. It returns why it
// ended ("signal" or "fatal_error") and the error, if any.
func (a *App) operate(ctx context.Context) (string, error) {
	if err := a.emitStarted(); err != nil {
		return "fatal_error", err
	}
	res, snap, buffered, err := a.reconcile(proctree.DiscoveryStartup)
	if err != nil {
		return "fatal_error", fmt.Errorf("startup reconciliation: %w", err)
	}
	if err := a.emitReady(res, snap, buffered); err != nil {
		return "fatal_error", err
	}
	debug.FreeOSMemory() // startup allocated the kernel BTF and the snapshot
	a.log.Info("observing", "watch", a.cfg.Watch.ImageContains, "kernel", a.col.Info().Kernel,
		"discovered_roots", res.Roots, "discovered_descendants", res.Descendants)

	now := time.Now()
	a.nextStats = now.Add(statsInterval)
	a.nextHealth = now.Add(a.cfg.Runtime.HealthInterval)
	a.nextReconcile = now.Add(a.cfg.Runtime.ReconcileInterval)
	a.lastReconcile = now
	// The loss baseline stays at the counters' state of the very start (zero):
	// whatever was lost since the hooks were attached, also while the startup
	// snapshot was taken and applied, is reported by the next poll at the latest.

	n := 0
	for {
		if ctx.Err() != nil {
			return "signal", nil
		}
		select {
		case err := <-a.fatal:
			return "fatal_error", err
		default:
		}
		ev, err := a.col.Next(time.Now().Add(readDeadline))
		switch {
		case err == nil:
			if err := a.engine.HandleEvent(ev); err != nil {
				return "fatal_error", fmt.Errorf("local log: %w", err)
			}
			n++
		case errors.Is(err, collector.ErrTimeout):
			n = housekeepingEvery // idle: do the periodic work now
		default:
			return "fatal_error", fmt.Errorf("collector: %w", err)
		}
		if n >= housekeepingEvery {
			n = 0
			if err := a.housekeeping(); err != nil {
				return "fatal_error", err
			}
		}
	}
}

// housekeeping runs the periodic work: loss detection, gap notices from the
// process model, reconciliation and health.
func (a *App) housekeeping() error {
	now := time.Now()
	if !now.Before(a.nextStats) {
		a.nextStats = now.Add(statsInterval)
		if err := a.pollKernelStats(now); err != nil {
			return err
		}
	}
	if a.engine.TakeReconcileHint() {
		a.scheduleReconcile(now)
	}
	for _, n := range a.engine.TakeNotices() {
		if err := a.emitGap(n.Cause, event.LostCounts{}, 0, n.Detail, "scheduled"); err != nil {
			return err
		}
		a.scheduleReconcile(now)
	}
	due := !now.Before(a.nextReconcile)
	if !a.reconcileAt.IsZero() && !now.Before(a.reconcileAt) {
		due = true
	}
	if due {
		a.reconcileAt = time.Time{}
		a.nextReconcile = now.Add(a.cfg.Runtime.ReconcileInterval)
		if _, _, _, err := a.reconcile(proctree.DiscoveryReconcile); err != nil {
			return err
		}
		a.lastReconcile = time.Now()
	}
	if !now.Before(a.nextHealth) {
		a.nextHealth = now.Add(a.cfg.Runtime.HealthInterval)
		if err := a.emitHealth(); err != nil {
			return err
		}
	}
	return nil
}

// scheduleReconcile asks for a reconciliation soon, but not more often than
// lossReconcileGap, so an overload cannot turn into a snapshot storm.
func (a *App) scheduleReconcile(now time.Time) {
	at := now
	if min := a.lastReconcile.Add(lossReconcileGap); at.Before(min) {
		at = min
	}
	if a.reconcileAt.IsZero() || at.Before(a.reconcileAt) {
		a.reconcileAt = at
	}
}

// pollKernelStats reads the kernel counters, which do not depend on ring
// buffer records, and reports every new loss as agent.gap.
func (a *App) pollKernelStats(now time.Time) error {
	return a.noteLoss(now, true)
}

// noteLoss compares the kernel's loss counters with the ones seen last. A new
// loss opens a gap in the process model and is reported as agent.gap; followUp
// schedules the reconciliation that compares the living processes again (not
// needed when one is running right now).
func (a *App) noteLoss(now time.Time, followUp bool) error {
	st, err := a.col.Stats()
	if err != nil {
		a.statsFailures++
		a.log.Warn("cannot read kernel counters", "error", err, "consecutive_failures", a.statsFailures)
		if a.statsFailures >= maxStatsFailures {
			return fmt.Errorf("the kernel loss counters could not be read %d times in a row, record loss would go unnoticed: %w", a.statsFailures, err)
		}
		return nil
	}
	a.statsFailures = 0
	if lost := st.Lost(); lost > a.lastLost {
		d := event.LostCounts{
			Fork: st.LostFork - a.lastStats.LostFork,
			Exec: st.LostExec - a.lastStats.LostExec,
			Exit: st.LostExit - a.lastStats.LostExit,
		}
		a.engine.MarkGap()
		if followUp {
			a.scheduleReconcile(now)
		}
		a.lastLost = lost
		a.lastStats = st
		return a.emitGap("ring_buffer_full", d, lost, "lifecycle records were lost in the kernel; the living processes are compared again, short-lived processes in the gap cannot be recovered", "scheduled")
	}
	a.lastStats = st
	return nil
}

// reconcile takes a snapshot of the living processes, collects the live
// records that arrived meanwhile and lets the process model merge both.
func (a *App) reconcile(mode string) (proctree.SnapshotResult, *collector.Snapshot, int, error) {
	snap, err := a.col.Snapshot()
	if err != nil {
		if mode == proctree.DiscoveryStartup {
			return proctree.SnapshotResult{}, nil, 0, err
		}
		a.log.Warn("reconciliation failed", "error", err)
		return proctree.SnapshotResult{}, nil, 0, a.emitGap("reconcile_failed", event.LostCounts{}, 0, err.Error(), "retry_next_interval")
	}
	pending := a.drain(snap)
	// Everything lost until now, the startup window included, makes the
	// relations this reconciliation admits unconfirmed: report it and open the
	// gap in the process model before the snapshot is applied.
	if err := a.noteLoss(time.Now(), false); err != nil {
		return proctree.SnapshotResult{}, snap, len(pending), err
	}
	res, err := a.engine.ApplySnapshot(snap, pending, mode)
	if err != nil {
		return res, snap, len(pending), err
	}
	if st, serr := a.col.Stats(); serr == nil && st.Lost() > a.lastLost {
		a.engine.MarkGap() // records were lost while the snapshot was applied; the next poll reports them
	}
	return res, snap, len(pending), nil
}

// drain reads the records that are available right now. They are older than,
// or concurrent with, the snapshot and must be merged with it before
// processing continues.
func (a *App) drain(snap *collector.Snapshot) []collector.Event {
	var pending []collector.Event
	for len(pending) < maxDrain {
		ev, err := a.col.Next(time.Now().Add(2 * time.Millisecond))
		if err != nil {
			break
		}
		pending = append(pending, ev)
		if ev.BootNS > snap.EndNS+uint64(100*time.Millisecond) {
			break // everything older than the snapshot is in
		}
	}
	return pending
}

// shutdown ends the run in this order: stop the capture, work
// off what was already read, finish the remote queues within the timeout,
// store agent.stopped locally and sync the file.
func (a *App) shutdown(reason string, runErr error) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.Runtime.ShutdownTimeout)
	defer cancel()

	// No new action may start while the agent shuts down: waiting ones are
	// completed as skipped (shutdown), the running one is finished.
	a.engine.DisableKill()
	if a.worker != nil {
		a.worker.Stop(ctx)
	}
	_ = a.col.StopCapture()
	// Records that were already captured are still processed (not after a fatal log error).
	if a.sink.Fatal() == nil && runErr == nil {
		a.drainOnShutdown(ctx)
	}
	undelivered := a.sink.CloseRemotes(ctx)
	if ring := a.col.Pending(); ring > 0 {
		undelivered["ring_buffer_bytes"] = ring
	}
	details := a.stoppedDetails(reason, runErr, undelivered)
	ev := a.factory.New(event.TypeAgentStopped, event.SourceAgent)
	ev.Details = details
	var errs []error
	if err := a.sink.Emit(ev); err != nil {
		a.log.Error("cannot store agent.stopped in the local log", "error", err)
		errs = append(errs, fmt.Errorf("store agent.stopped: %w", err))
	}
	if err := a.file.Sync(); err != nil {
		a.log.Error("final sync of the local log failed", "error", err)
		errs = append(errs, fmt.Errorf("final sync of the local log: %w", err))
	}
	return errors.Join(errs...)
}

func (a *App) drainOnShutdown(ctx context.Context) {
	limit := time.Now().Add(shutdownDrainLimit)
	for time.Now().Before(limit) && ctx.Err() == nil {
		ev, err := a.col.Next(time.Now().Add(5 * time.Millisecond))
		if err != nil {
			return
		}
		if err := a.engine.HandleEvent(ev); err != nil {
			return
		}
	}
}
