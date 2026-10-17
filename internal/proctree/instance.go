package proctree

import (
	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/response"
)

// Instance is one tracked process instance, identified by its collector.Key.
// An instance stays in memory while it is alive or while a retained
// descendant still needs it for its lineage; abandoned instances are released
// (see Engine.release), which bounds the memory by max_processes.
type Instance struct {
	Key collector.Key
	ID  string // boot_id:tgid:start_boot_ns

	Role   string
	Depth  int
	Root   *Instance // itself for roots
	Parent *Instance // creating process, nil for roots

	parentOut *event.Parent // stored excerpt of the creator, nil if unknown
	rootOut   *event.Root   // set on roots

	// admitImage is the image the root had when it was admitted; later execs
	// never overwrite it.
	admitImage *string

	// Current attributes.
	Image          string
	ImageOK        bool
	ImageTruncated bool
	ImageState     string
	Path           collector.Path
	Comm           string
	UID, EUID, GID uint32
	Args           collector.Args
	ArgsState      string // executed, inherited or snapshot; "" if never obtained
	ExecIndex      int

	// GapAffected marks instances whose place in the tree is not backed by
	// observed fork records (admitted by a reconciliation that followed a loss,
	// or by the exec of a process whose fork was missed). No kill action is
	// taken for them.
	GapAffected bool
	// parentUnknown: a root was admitted without knowing its parent.
	parentUnknown bool

	knownSince uint64 // kernel time of the first record about the instance
	visitNS    uint64 // snapshot visit time; older records are already reflected

	alive    bool
	released bool
	refs     int // retained instances that reference this one as their parent

	live         response.Liveness
	killDoneExec int // exec index of the last kill decision, -1 if none
	ActionID     string
}

// complete is the lineage.complete value: the chain from the root is backed
// by observed relations and the parent of a root was known.
func (i *Instance) complete() bool { return !i.GapAffected && !i.parentUnknown }
