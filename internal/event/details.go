package event

// Details of process events. The structs are serialized in field order.

// ForkDetails of process.fork.
type ForkDetails struct {
	// CreatorTID is the kernel thread id that called clone/fork; it differs
	// from the creator's pid when a non-leader thread forked.
	CreatorTID uint32 `json:"creator_tid"`
}

// DiscoveredDetails of process.discovered: a living process was assigned to
// the observed tree for the first time. It is not an invented fork.
type DiscoveredDetails struct {
	Discovery   string `json:"discovery"`     // "startup" or "reconcile"
	VisitBootNS string `json:"visit_boot_ns"` // when the snapshot looked at the process
	ExecIndex   int    `json:"exec_index"`    // 0: no exec was observed for this instance
}

// ExecDetails of process.exec.
type ExecDetails struct {
	// ExecIndex counts the successful execs observed for this instance, from 1.
	ExecIndex int `json:"exec_index"`
	// ExecFilename is the path as requested by the caller (a script name for
	// scripts); the executed program is process.image / process.image_path.
	ExecFilename  *string `json:"exec_filename"`
	PreviousImage *string `json:"previous_image"`
	ThreadExec    bool    `json:"thread_exec"` // exec was called by a non-leader thread
}

// ExitDetails of process.exit. Values that were not observed are null.
type ExitDetails struct {
	ExitCode   *int    `json:"exit_code"`
	Signal     *int    `json:"signal"`
	CoreDumped *bool   `json:"core_dumped"`
	DurationNS *string `json:"duration_ns"`
	// ExitSource is "kernel" for an observed exit and "inferred" when the
	// reconciliation found the process gone without an exit record.
	ExitSource string `json:"exit_source"`
	// ResponseActionID correlates the exit with a kill action taken for this
	// instance. It states a correlation, not a causal claim.
	ResponseActionID *string `json:"response_action_id"`
}

// Agent events.

// StartedDetails of agent.started: sent before the startup reconciliation is
// finished; nothing is claimed about completeness.
type StartedDetails struct {
	Version            string   `json:"version"`
	PID                int      `json:"pid"`
	Kernel             string   `json:"kernel"`
	Arch               string   `json:"arch"`
	Phase              string   `json:"phase"` // "initializing"
	CompleteCapture    bool     `json:"complete_capture"`
	HooksActiveBootNS  string   `json:"hooks_active_boot_ns"`
	HistoryBeforeHooks string   `json:"history_before_hooks"` // "unknown"
	ConfigSource       string   `json:"config_source"`
	WatchImageContains []string `json:"watch_image_contains"`
	CaptureArgv        bool     `json:"capture_argv"`
	// ArgvLimits are the argument capture limits in effect; null when capture_argv is false.
	ArgvLimits *ArgvLimits `json:"capture_argv_limits"`
	Outputs    []string    `json:"outputs"`
	Kill       KillStatus  `json:"kill"`
	LogRepair  *LogRepair  `json:"log_repair"`
}

// ArgvLimits are the limits of the argument capture.
type ArgvLimits struct {
	MaxArgs  int `json:"max_args"`
	MaxBytes int `json:"max_bytes"`
}

// KillStatus is the kill feature configuration summary.
type KillStatus struct {
	Enabled bool     `json:"enabled"`
	DryRun  bool     `json:"dry_run"`
	Fields  []string `json:"fields"`
	Rules   int      `json:"rules"`
	// SpareRootImage mirrors kill.spare_root_image.
	SpareRootImage bool `json:"spare_root_image"`
	// Warnings name rules that probably do more than intended (for example a
	// rule that matches the watched service itself).
	Warnings []string `json:"warnings"`
}

// LogRepair reports the repair of a torn last line in the local log.
type LogRepair struct {
	Repaired bool   `json:"repaired"`
	Bytes    int64  `json:"bytes"`
	SavedAs  string `json:"saved_as"`
}

// ReadyDetails of agent.ready: hooks are active and the snapshot and the
// buffered live records are reconciled.
type ReadyDetails struct {
	ObservingSinceBootNS string `json:"observing_since_boot_ns"`
	SnapshotStartBootNS  string `json:"snapshot_start_boot_ns"`
	SnapshotEndBootNS    string `json:"snapshot_end_boot_ns"`
	SnapshotProcesses    int    `json:"snapshot_processes"`
	DiscoveredRoots      int    `json:"discovered_roots"`
	DiscoveredProcesses  int    `json:"discovered_descendants"`
	BufferedRecords      int    `json:"buffered_records"`
	Note                 string `json:"note"`
}

// GapDetails of agent.gap.
type GapDetails struct {
	Cause string `json:"cause"` // ring_buffer_full, process_table_full, reconcile_failed
	// Lost is the number of records lost since the previous report.
	Lost      LostCounts `json:"lost"`
	LostTotal uint64     `json:"lost_total"`
	Message   string     `json:"message"`
	Reconcile string     `json:"reconcile"` // "scheduled": the living processes are compared again
}

// LostCounts are kernel record losses per record type.
type LostCounts struct {
	Fork uint64 `json:"fork"`
	Exec uint64 `json:"exec"`
	Exit uint64 `json:"exit"`
}

// HealthDetails of agent.health. Counters are cumulative for the current run.
// TCP and UDP "handed_over" mean handed to the transport, never acknowledged
// by the receiver.
type HealthDetails struct {
	UptimeNS  string                 `json:"uptime_ns"`
	Tracked   TrackedStats           `json:"tracked"`
	Collector CollectorStats         `json:"collector"`
	Events    map[string]uint64      `json:"events"`
	Filter    FilterStats            `json:"filter"`
	Outputs   map[string]OutputStats `json:"outputs"`
	Response  *ResponseStats         `json:"response"`
}

// TrackedStats describes the process table.
type TrackedStats struct {
	Roots     int  `json:"roots"`
	Instances int  `json:"instances"`
	Retained  int  `json:"retained"`
	Limit     int  `json:"limit"`
	GapOpen   bool `json:"gap_open"`
}

// CollectorStats are the kernel side counters.
type CollectorStats struct {
	Lost           LostCounts `json:"lost"`
	LostTotal      uint64     `json:"lost_total"`
	Records        LostCounts `json:"records"`
	ThreadClones   uint64     `json:"thread_clones_skipped"`
	DuplicateExits uint64     `json:"duplicate_exits_dropped"`
	PathErrors     uint64     `json:"path_errors"`
	ArgsErrors     uint64     `json:"args_errors"`
	RingPending    int        `json:"ring_pending_bytes"`
	TableFull      uint64     `json:"process_table_full"`
	LiveTableOOR   uint64     `json:"live_table_out_of_range"`
}

// FilterStats counts exclusions and the depth limit.
type FilterStats struct {
	ExcludedRemote uint64 `json:"excluded_remote"`
	ExcludedAll    uint64 `json:"excluded_all"`
	DepthSuppress  uint64 `json:"suppressed_by_depth"`
}

// OutputStats are the per-output delivery counters.
type OutputStats struct {
	QueueLen         int    `json:"queue_len,omitempty"`
	HandedOver       uint64 `json:"handed_over"`
	DroppedQueueFull uint64 `json:"dropped_queue_full"`
	DroppedTooLarge  uint64 `json:"dropped_too_large,omitempty"`
	DroppedShutdown  uint64 `json:"dropped_shutdown,omitempty"`
	Failed           uint64 `json:"failed"`
	Retries          uint64 `json:"retries"`
	Lines            uint64 `json:"lines,omitempty"`
	Bytes            uint64 `json:"bytes,omitempty"`
	Rotations        uint64 `json:"rotations,omitempty"`
}

// ResponseStats are the kill feature counters (agent.health).
type ResponseStats struct {
	RuleHits         uint64            `json:"rule_hits"`
	SignalAttempts   uint64            `json:"signal_attempts"`
	SignalsAccepted  uint64            `json:"signals_accepted"`
	AlreadyExited    uint64            `json:"already_exited"`
	PermissionDenied uint64            `json:"permission_denied"`
	Errors           uint64            `json:"errors"`
	DryRun           uint64            `json:"dry_run"`
	Skipped          map[string]uint64 `json:"skipped"`
	QueueLen         int               `json:"queue_len"`
	QueueCap         int               `json:"queue_cap"`
	LatencyCount     uint64            `json:"latency_samples"`
	LatencyAvgNS     uint64            `json:"latency_avg_ns"`
	LatencyMaxNS     uint64            `json:"latency_max_ns"`
}

// StoppedDetails of agent.stopped.
type StoppedDetails struct {
	Reason       string                 `json:"reason"` // "signal", "fatal_error", "collector_closed"
	Error        *string                `json:"error"`
	UptimeNS     string                 `json:"uptime_ns"`
	Collector    CollectorStats         `json:"collector"`
	Events       map[string]uint64      `json:"events"`
	Filter       FilterStats            `json:"filter"`
	Outputs      map[string]OutputStats `json:"outputs"`
	Response     *ResponseStats         `json:"response"`
	UndeliveredN map[string]int         `json:"undelivered_at_shutdown"`
}

// Response audit events.

// Outcomes of response.kill_result (and "pending" in response.kill_requested).
const (
	OutcomePending          = "pending"
	OutcomeDryRun           = "dry_run"
	OutcomeSignalSent       = "signal_sent"
	OutcomeAlreadyExited    = "already_exited"
	OutcomePermissionDenied = "permission_denied"
	OutcomeSkipped          = "skipped"
	OutcomeError            = "error"
)

// Reasons of a skipped outcome.
const (
	SkipIdentityUnverified = "identity_unverified"
	SkipIdentityMismatch   = "identity_mismatch"
	SkipMatchNoLongerVerif = "match_no_longer_verified"
	SkipActionQueueFull    = "action_queue_full"
	SkipShutdown           = "shutdown"
	SkipLineageUnconfirmed = "lineage_unconfirmed"
	SkipRootImageSpared    = "root_image_spared"
	SkipActionsDisabled    = "actions_stopped"
	SkipAlreadyAttempted   = "already_attempted"
)

// RuleHit is one kill rule that matched.
type RuleHit struct {
	Ref      string `json:"ref"`  // stable reference, e.g. kill.regex[0]
	Type     string `json:"type"` // "string" or "regex"
	Pattern  string `json:"pattern"`
	Field    string `json:"field"` // image, image_path or argv
	ArgIndex *int   `json:"arg_index,omitempty"`
}

// SysError is a machine readable system error.
type SysError struct {
	Errno   string `json:"errno"`
	Code    int    `json:"code"`
	Message string `json:"message"`
	Op      string `json:"op"` // which call failed: pidfd_open, pidfd_send_signal, identity
}

// KillDetails of response.kill_requested and response.kill_result.
type KillDetails struct {
	ActionID       string    `json:"action_id"`
	TriggerEventID string    `json:"trigger_event_id"`
	TriggerType    string    `json:"trigger_event_type"`
	Action         string    `json:"action"` // "kill"
	Signal         string    `json:"signal"` // "SIGKILL"
	DryRun         bool      `json:"dry_run"`
	ExecIndex      int       `json:"exec_index"`
	Rules          []RuleHit `json:"rules"`
	Outcome        string    `json:"outcome"`
	Reason         *string   `json:"reason"`
	Error          *SysError `json:"error"`
	// Times: the kernel time of the triggering record, the decision and the
	// signal attempt; distances are in nanoseconds.
	TriggerBootNS       string  `json:"trigger_boot_ns"`
	DecidedAt           Time    `json:"decided_at"`
	DecidedBootNS       string  `json:"decided_boot_ns"`
	SignalAttemptedAt   *Time   `json:"signal_attempted_at"`
	SignalAttemptBootNS *string `json:"signal_attempt_boot_ns"`
	DecisionLatencyNS   string  `json:"decision_latency_ns"`
	AttemptLatencyNS    *string `json:"attempt_latency_ns"`
	// Chain lists the ancestors of the target from the root down to its direct
	// parent with their executables and arguments as they were when the decision
	// was made: the decision explains itself even when the events of the ancestors
	// are not at hand (excluded, beyond the depth limit, in another log). It is
	// bounded; ChainTruncated says that ancestors between the root and the nearest
	// ones are left out.
	Chain          []ChainLink `json:"chain"`
	ChainTruncated bool        `json:"chain_truncated"`
}

// ChainLink is one ancestor in KillDetails.Chain.
type ChainLink struct {
	ProcessID string  `json:"process_id"`
	PID       uint32  `json:"pid"`
	Image     *string `json:"image"`
	ImagePath *string `json:"image_path"`
	ExecIndex int     `json:"exec_index"`
	// Argv is the argument vector of the ancestor, limited in size; null when the
	// arguments are not captured or not available. ArgvComplete is false when the
	// ancestor's own capture was incomplete or the size limit of the chain cut it.
	Argv         []string `json:"argv"`
	ArgvComplete *bool    `json:"argv_complete"`
}
