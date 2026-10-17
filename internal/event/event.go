// Package event defines the JSONL event contract (schema_version 1) and its
// serialization. One event is one JSON object on one line.
package event

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// SchemaVersion is the version of the event contract.
const SchemaVersion = 1

// Event types.
const (
	TypeProcessDiscovered = "process.discovered"
	TypeProcessFork       = "process.fork"
	TypeProcessExec       = "process.exec"
	TypeProcessExit       = "process.exit"
	TypeAgentStarted      = "agent.started"
	TypeAgentReady        = "agent.ready"
	TypeAgentHealth       = "agent.health"
	TypeAgentGap          = "agent.gap"
	TypeAgentStopped      = "agent.stopped"
	TypeKillRequested     = "response.kill_requested"
	TypeKillResult        = "response.kill_result"
)

// Event sources.
const (
	SourceEBPF     = "ebpf"
	SourceSnapshot = "snapshot"
	SourceAgent    = "agent"
)

// Image states: where the image/argv information of a process event comes from.
const (
	StateInherited = "inherited" // fork: the creator's image
	StateExecuted  = "executed"  // observed at a successful exec
	StateSnapshot  = "snapshot"  // read from the running system
)

// Roles in the observed tree.
const (
	RoleRoot       = "root"
	RoleDescendant = "descendant"
)

// Parent relationship sources.
const (
	RelFork         = "fork"             // creator reported by the fork hook
	RelSnapshotPPID = "snapshot_ppid"    // current parent at snapshot time
	RelExecParent   = "exec_real_parent" // real parent at the exec of an unknown process
)

// Time marshals as UTC RFC 3339 with exactly nine fractional digits.
type Time time.Time

const timeLayout = "2006-01-02T15:04:05.000000000Z"

func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Time(t).UTC().Format(timeLayout) + `"`), nil
}

// UnmarshalJSON parses the timestamp form written by MarshalJSON.
func (t *Time) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return err
	}
	*t = Time(parsed)
	return nil
}

// Event is the common envelope of every JSONL line. Field order is the
// serialization order.
type Event struct {
	SchemaVersion   int         `json:"schema_version"`
	EventID         string      `json:"event_id"`
	AgentInstanceID string      `json:"agent_instance_id"`
	Sequence        uint64      `json:"sequence"`
	EventType       string      `json:"event_type"`
	Timestamp       Time        `json:"timestamp"`
	ObservedAt      Time        `json:"observed_at"`
	BootTimeNS      *string     `json:"boot_time_ns"`
	Host            Host        `json:"host"`
	Source          string      `json:"source"`
	Process         *Process    `json:"process"`
	Parent          *Parent     `json:"parent"`
	Root            *Root       `json:"root"`
	Lineage         *Lineage    `json:"lineage"`
	Filter          Filter      `json:"filter"`
	DataQuality     DataQuality `json:"data_quality"`
	Details         any         `json:"details"`
}

// Host identifies the machine and its boot.
type Host struct {
	Hostname string `json:"hostname"`
	BootID   string `json:"boot_id"`
}

// Process describes the (target) process instance.
type Process struct {
	ProcessID    string   `json:"process_id"`
	PID          uint32   `json:"pid"`
	StartBootNS  string   `json:"start_boot_ns"`
	Image        *string  `json:"image"`
	ImageState   string   `json:"image_state"`
	ImagePath    *string  `json:"image_path"`
	ImageDeleted *bool    `json:"image_deleted,omitempty"`
	Comm         *string  `json:"comm"`
	UID          uint32   `json:"uid"`
	EUID         uint32   `json:"euid"`
	GID          uint32   `json:"gid"`
	Argv         []string `json:"argv"`
	ArgvState    *string  `json:"argv_state"`
}

// Parent is the stored metadata excerpt of the creating process.
type Parent struct {
	ProcessID          string  `json:"process_id"`
	PID                uint32  `json:"pid"`
	Image              *string `json:"image"`
	ImagePath          *string `json:"image_path,omitempty"`
	RelationshipSource string  `json:"relationship_source"`
}

// Root references the process that caused the tree to be observed. Image is
// the image it had when it was admitted and is never overwritten.
type Root struct {
	ProcessID string  `json:"process_id"`
	PID       uint32  `json:"pid"`
	Image     *string `json:"image"`
}

// Lineage describes the position in the observed tree.
type Lineage struct {
	Role               string   `json:"role"`
	Depth              int      `json:"depth"`
	Ancestors          []string `json:"ancestors"`
	AncestorsTruncated bool     `json:"ancestors_truncated"`
	Complete           bool     `json:"complete"`
}

// MaxAncestors bounds the serialized ancestors array.
const MaxAncestors = 64

// Filter is the exclusion outcome of a process event.
type Filter struct {
	Excluded          bool          `json:"excluded"`
	Matches           []FilterMatch `json:"matches"`
	SuppressedOutputs []string      `json:"suppressed_outputs"`
}

// FilterMatch names the exclusion field and the configured string that hit.
type FilterMatch struct {
	Field string `json:"field"`
	Value string `json:"value"`
	Index *int   `json:"index,omitempty"` // argument index for field argv
}

// DataQuality records what is missing, cut or affected by a collection gap.
type DataQuality struct {
	MissingFields   []Missing `json:"missing_fields"`
	TruncatedFields []string  `json:"truncated_fields"`
	SanitizedFields []string  `json:"sanitized_fields"`
	CollectionGap   bool      `json:"collection_gap"`
}

// Missing explains a null value with a machine readable reason.
type Missing struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// Reasons used in Missing.Reason.
const (
	ReasonKernelUnavailable = "kernel_unavailable" // the kernel could not read it
	ReasonProcUnavailable   = "proc_unavailable"   // /proc read failed (snapshot)
	ReasonProcessExited     = "process_exited"     // gone before it could be read
	ReasonIdentityMismatch  = "identity_mismatch"  // the pid belongs to another instance now
	ReasonNotCaptured       = "not_captured"       // never collected for this event
	ReasonNotObserved       = "not_observed"       // the event that carries it was not observed
)

// NewUUID returns a random (version 4) UUID.
func NewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("event: no randomness: %v", err))
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Str returns a pointer to s, for optional string fields.
func Str(s string) *string { return &s }

// StrNS formats a nanosecond value as the decimal string the contract uses.
func StrNS(ns uint64) *string {
	s := fmt.Sprintf("%d", ns)
	return &s
}

// ProcessID builds the stable instance identity boot_id:tgid:start_boot_ns.
func ProcessID(bootID string, tgid uint32, startNS uint64) string {
	return fmt.Sprintf("%s:%d:%d", bootID, tgid, startNS)
}

// MarshalLine serializes the event as one JSON object followed by a newline.
// HTML escaping is off (process data is not HTML) and invalid UTF-8 cannot
// occur because callers sanitize process strings with Sanitize first.
func (e *Event) MarshalLine() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil // Encode already appended the newline
}

// Sanitize makes s valid UTF-8 by replacing every invalid byte with U+FFFD
// (so the number of damaged bytes stays visible). The boolean tells whether
// anything was replaced.
func Sanitize(s string) (string, bool) {
	if utf8.ValidString(s) {
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteString("\uFFFD")
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String(), true
}
