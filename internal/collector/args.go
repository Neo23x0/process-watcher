package collector

import "bytes"

// Defaults and bounds of the argument capture. The defaults are what the
// agent used before the limits became configurable.
const (
	DefaultMaxArgs     = 32
	DefaultMaxArgBytes = 4096

	// MinMaxArgs and CeilingMaxArgs bound the configurable argument count.
	MinMaxArgs     = 1
	CeilingMaxArgs = 1024
	// MinMaxArgBytes and CeilingMaxArgBytes bound the configurable number of raw
	// argument bytes. The ceiling is the size of the kernel side scratch buffer
	// (see PW_ARGS_MASK in collector.bpf.c); it cannot be raised without a new
	// object that has passed the verifier on every supported kernel.
	MinMaxArgBytes     = 256
	CeilingMaxArgBytes = 16383
)

// ArgLimits are the limits of the argument capture in effect: at most MaxArgs
// arguments and MaxBytes raw bytes (arguments plus their NUL terminators) per
// exec. The zero value selects the defaults.
type ArgLimits struct {
	MaxArgs  int
	MaxBytes int
}

// DefaultArgLimits returns the defaults (32 arguments, 4096 bytes).
func DefaultArgLimits() ArgLimits {
	return ArgLimits{MaxArgs: DefaultMaxArgs, MaxBytes: DefaultMaxArgBytes}
}

// Normalized replaces zero values by the defaults.
func (l ArgLimits) Normalized() ArgLimits {
	if l.MaxArgs <= 0 {
		l.MaxArgs = DefaultMaxArgs
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultMaxArgBytes
	}
	return l
}

// ArgsState says whether and how the arguments of an exec were obtained.
type ArgsState uint8

const (
	ArgsNotCaptured ArgsState = iota // capture disabled
	ArgsCaptured                     // List holds the complete arguments that fit the limits
	ArgsFailed                       // capture enabled but reading the memory failed
)

// PartialArg is the argument that the byte limit cut: only its first bytes
// were captured. It is investigation evidence and nothing else: it is never
// part of List and never reaches an exclusion or a kill rule, because a prefix
// is not the value (an end anchor such as "^useradd$" must not match the cut
// "useradd-long-name").
type PartialArg struct {
	Index int    // position in the argument vector, equal to len(List)
	Value string // the captured prefix of the argument
}

// Args is the captured argument vector. List only contains arguments that were
// captured completely, so every element is a trustworthy value.
type Args struct {
	State ArgsState
	List  []string
	// Truncated is set when the vector is longer than what was captured (more
	// than the argument limit or more than the byte limit). The last, partially
	// captured argument is not part of List; it is kept in Partial.
	Truncated bool
	// Argc is the argument count reported by the kernel, 0 if unknown.
	Argc int
	// TotalBytes is the size of the raw argument area at exec as the kernel saw
	// it, 0 if unknown (arguments read later from /proc).
	TotalBytes int
	// CapturedBytes is the number of raw bytes that were captured.
	CapturedBytes int
	// Partial is the cut argument, nil when the capture ended on an argument
	// boundary or at the argument limit.
	Partial *PartialArg
	// Limits are the limits that were in effect for this capture.
	Limits ArgLimits
}

// Complete reports whether List is the whole argument vector.
func (a Args) Complete() bool { return a.State == ArgsCaptured && !a.Truncated }

// ParseArgs splits a raw NUL separated argument block. rawCut tells that the
// capture stopped at the byte limit; argc is the kernel's argument count and
// total the size of the raw argument area (0 if unknown).
func ParseArgs(raw []byte, rawCut bool, argc, total int, lim ArgLimits) Args {
	lim = lim.Normalized()
	a := Args{State: ArgsCaptured, Argc: argc, TotalBytes: total, CapturedBytes: len(raw), Limits: lim}
	rest := raw
	for len(rest) > 0 {
		i := bytes.IndexByte(rest, 0)
		if i < 0 {
			// Last argument without terminator: it was cut. Keep what was captured,
			// separate from the list.
			a.Truncated = true
			a.Partial = &PartialArg{Index: len(a.List), Value: string(rest)}
			break
		}
		if len(a.List) == lim.MaxArgs {
			a.Truncated = true
			break
		}
		a.List = append(a.List, string(rest[:i]))
		rest = rest[i+1:]
	}
	if rawCut {
		a.Truncated = true
	}
	if argc > len(a.List) {
		a.Truncated = true
	}
	return a
}
