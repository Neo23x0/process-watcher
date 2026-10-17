// Package collector defines the platform independent view of the kernel
// process lifecycle events: the raw event model, the Collector interface and
// helpers shared by the real eBPF collector and the replay collector used in
// tests.
package collector

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrTimeout is returned by Next when the deadline passed without a record.
	ErrTimeout = errors.New("collector: no record before deadline")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("collector: closed")
	// ErrUnsupported is returned on platforms without a collector.
	ErrUnsupported = errors.New("collector: unsupported platform")
)

// PrerequisiteError reports a missing kernel feature, permission or
// environment property together with a concrete diagnosis. The agent exits
// with code 3 for it.
type PrerequisiteError struct {
	Check  string // short name of the failed check
	Detail string // human readable explanation incl. the remedy
	Err    error  // underlying error, may be nil
}

func (e *PrerequisiteError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Check, e.Detail, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Check, e.Detail)
}

func (e *PrerequisiteError) Unwrap() error { return e.Err }

// Key identifies one process instance within a boot: the host thread group id
// and the exact kernel start time (CLOCK_BOOTTIME nanoseconds of the thread
// group leader). The pair is read from the same kernel field by the live hooks
// and the snapshot iterator.
type Key struct {
	TGID    uint32
	StartNS uint64
}

// IsZero reports whether k is the zero key (unknown process).
func (k Key) IsZero() bool { return k == Key{} }

// Kind is the type of a lifecycle record.
type Kind uint8

const (
	KindFork Kind = iota + 1
	KindExec
	KindExit
)

func (k Kind) String() string {
	switch k {
	case KindFork:
		return "fork"
	case KindExec:
		return "exec"
	case KindExit:
		return "exit"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// Event is one lifecycle record in ring buffer order.
type Event struct {
	Kind   Kind
	BootNS uint64 // CLOCK_BOOTTIME when the kernel built the record
	// Proc is the new child (fork) or the acting process (exec, exit).
	Proc Key
	// Parent is the creating process (fork, also for CLONE_PARENT) or the real
	// parent at exec time; zero when unknown.
	Parent Key
	// TID is the creating thread (fork), the thread that called exec, or the
	// last exiting thread.
	TID            uint32
	UID, EUID, GID uint32
	Comm           string
	Exec           ExecInfo // KindExec only
	// ExitStatus is a wait(2) style status (KindExit only): code<<8 for a
	// normal exit, the signal number (|0x80 with core dump) otherwise.
	ExitStatus int32
}

// ExecInfo carries what the kernel read at a successful exec.
type ExecInfo struct {
	// Image is the file name of the executed program (basename of the dentry,
	// the interpreter for scripts), never argv[0].
	Image          string
	ImageOK        bool // false when the kernel could not read the name
	ImageTruncated bool
	Path           Path
	// Filename is the path as requested by the caller of execve (script name,
	// relative path, /dev/fd/N/...).
	Filename          string
	FilenameOK        bool
	FilenameTruncated bool
	ParentComm        string
	ParentImage       string
	FromThread        bool   // exec was called by a non-leader thread
	TIDBefore         uint32 // thread id that called exec
	Args              Args
}

// Path is the absolute path of the executed file as built in the kernel.
type Path struct {
	Value     string
	Known     bool // false when the kernel could not build a path
	Truncated bool // Value is only a suffix
	Deleted   bool // the file was unlinked (memfd and deleted binaries)
}

// SnapProc is one living process from the task iterator snapshot.
type SnapProc struct {
	Key     Key
	Parent  Key    // current real parent at visit time
	VisitNS uint64 // when the iterator looked at the task
	UID     uint32
	EUID    uint32
	GID     uint32
	Threads uint32
	Comm    string
	Image   string
	ImageOK bool
	Path    Path
	NoMM    bool // leader without mm (zombie leader with live threads)
}

// Snapshot is a consistent-enough list of living processes. StartNS and EndNS
// bracket the iteration in CLOCK_BOOTTIME nanoseconds.
type Snapshot struct {
	StartNS uint64
	EndNS   uint64
	Procs   []SnapProc
}

// Stats are kernel side counters; they never depend on a ring buffer record
// being delivered. Values are cumulative since the collector started.
type Stats struct {
	LostFork, LostExec, LostExit uint64
	Fork, Exec, Exit             uint64
	ThreadClones                 uint64
	KernelThreads                uint64
	ThreadExits                  uint64
	LiveOutOfRange               uint64
	ScratchErrors                uint64
	ArgsErrors                   uint64
	PathErrors                   uint64
	// DuplicateExits counts exit records dropped because another thread of the
	// same process had already reported its end (computed in Go).
	DuplicateExits uint64
}

// Lost is the total number of records the kernel could not deliver.
func (s Stats) Lost() uint64 { return s.LostFork + s.LostExec + s.LostExit }

// Info describes a started collector.
type Info struct {
	Kernel        string // uname release
	Arch          string
	RingBytes     int
	HooksActiveNS uint64 // CLOCK_BOOTTIME after the last hook was attached
	CaptureArgs   bool
	LiveTable     bool
}

// Options configures a collector.
type Options struct {
	// RingBufferBytes is the BPF ring buffer size, a power of two.
	RingBufferBytes int
	// CaptureArgs captures raw argv at every exec (privacy sensitive).
	CaptureArgs bool
	// LiveTable maintains the tgid -> start time table used to verify the exact
	// identity of a pid right before a signal is sent.
	LiveTable bool
}

// Collector is the source of lifecycle records and snapshots.
type Collector interface {
	// Next returns the next record in kernel ring order. It returns ErrTimeout
	// when the deadline passes first and ErrClosed after Close.
	Next(deadline time.Time) (Event, error)
	// Pending is the number of bytes in the kernel buffer that Next has not
	// returned yet; zero means the reader has caught up.
	Pending() int
	// Snapshot enumerates the living processes with the same identity fields
	// as the live records.
	Snapshot() (*Snapshot, error)
	// Stats reads the kernel counters.
	Stats() (Stats, error)
	// LiveStart returns the exact kernel start time of the process that
	// currently owns tgid, or 0 if none. Requires Options.LiveTable.
	LiveStart(tgid uint32) (uint64, error)
	// Info describes the running collector.
	Info() Info
	// StopCapture detaches the hooks. Records already in the kernel buffer can
	// still be read with Next afterwards (shutdown drains them).
	StopCapture() error
	// Close detaches the hooks and releases all resources.
	Close() error
}
