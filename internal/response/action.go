// Package response executes the rule based termination of observed
// descendant processes (the kill feature): a bounded action path with one
// worker that verifies the exact process identity through a pidfd and sends
// SIGKILL to that single process, and writes the audit events.
package response

import (
	"sync/atomic"
	"time"

	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/killrule"
)

// QueueCap is the maximum number of waiting actions.
const QueueCap = 256

// Liveness is shared between the process model (which updates it from the
// event stream) and the worker (which reads it right before the signal).
type Liveness struct {
	// ExecIndex is the number of successful execs observed for the instance.
	ExecIndex atomic.Int32
	// Alive turns false when the exit of the instance was observed.
	Alive atomic.Bool
}

// Action is the decision to kill one process instance. It is immutable after
// Submit; the target description is a copy taken at decision time, so the
// worker never touches the process model.
type Action struct {
	ID             string
	TriggerEventID string
	TriggerType    string
	TriggerBootNS  uint64
	DecidedAt      time.Time
	DecidedBootNS  uint64
	DryRun         bool

	// Key is the exact identity: boot id (agent run), tgid and kernel start time.
	Key       collector.Key
	ExecIndex int
	Hits      []killrule.Hit
	Live      *Liveness

	// Audit data of the target as it was when the decision was made.
	Process     *event.Process
	Parent      *event.Parent
	Root        *event.Root
	Lineage     *event.Lineage
	DataQuality event.DataQuality
	// Chain are the ancestors with their arguments (root first), see event.KillDetails.
	Chain          []event.ChainLink
	ChainTruncated bool

	// RequestedEventID is the event id of the response.kill_requested event.
	RequestedEventID string
}

// Responder accepts actions. Submit never blocks: when the bounded queue is
// full the action is completed as skipped (action_queue_full).
type Responder interface {
	Submit(a *Action)
	// Skip records an action that is not executed (for example because the
	// lineage is unconfirmed) without queueing it.
	Skip(a *Action, reason string)
}
