package collector

import "bytes"

// Limits of the argument capture (32 arguments, 4096 bytes).
const (
	MaxArgs     = 32
	MaxArgBytes = 4096
)

// ArgsState says whether and how the arguments of an exec were obtained.
type ArgsState uint8

const (
	ArgsNotCaptured ArgsState = iota // capture disabled
	ArgsCaptured                     // List holds the complete arguments that fit the limits
	ArgsFailed                       // capture enabled but reading the memory failed
)

// Args is the captured argument vector. List only contains arguments that were
// captured completely, so every element is a trustworthy value.
type Args struct {
	State ArgsState
	List  []string
	// Truncated is set when the vector is longer than what was captured (more
	// than MaxArgs arguments or more than MaxArgBytes raw bytes). The last,
	// partially captured argument is not part of List.
	Truncated bool
	// Argc is the argument count reported by the kernel, 0 if unknown.
	Argc int
}

// ParseArgs splits a raw NUL separated argument block. rawCut tells that the
// kernel stopped copying at MaxArgBytes; argc is the kernel's argument count
// (0 if unknown).
func ParseArgs(raw []byte, rawCut bool, argc int) Args {
	a := Args{State: ArgsCaptured, Argc: argc}
	for len(raw) > 0 {
		i := bytes.IndexByte(raw, 0)
		if i < 0 {
			// Last argument without terminator: it was cut, drop it.
			a.Truncated = true
			break
		}
		if len(a.List) == MaxArgs {
			a.Truncated = true
			break
		}
		a.List = append(a.List, string(raw[:i]))
		raw = raw[i+1:]
	}
	if rawCut {
		a.Truncated = true
	}
	if argc > len(a.List) {
		a.Truncated = true
	}
	return a
}
