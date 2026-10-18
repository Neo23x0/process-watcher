package ebpf

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/Neo23x0/process-watcher/internal/collector"
)

// Record types, mirrors enum pw_event_type in bpf/pw.h.
const (
	evFork uint32 = 1
	evExec uint32 = 2
	evExit uint32 = 3
)

// Fixed part sizes, mirror the structs in bpf/pw.h.
const (
	hdrSize       = 16
	forkSize      = 72
	exitSize      = 40
	execFixedSize = 112
	snapFixedSize = 80
	maxSnapRecord = snapFixedSize + 4096
)

// Field offsets. TestWireContract compares every one of them with the BTF of
// the embedded object, so they cannot drift from bpf/pw.h unnoticed.
const (
	hdrType  = 0
	hdrSizeF = 4
	hdrKtime = 8

	forkParentStart = 16
	forkChildStart  = 24
	forkParentTGID  = 32
	forkParentTID   = 36
	forkChildTGID   = 40
	forkUID         = 44
	forkEUID        = 48
	forkGID         = 52
	forkComm        = 56

	exitStart  = 16
	exitTGID   = 24
	exitTID    = 28
	exitStatus = 32
	exitFlags  = 36

	execStart          = 16
	execParentStart    = 24
	execTGID           = 32
	execTIDBefore      = 36
	execUID            = 40
	execEUID           = 44
	execGID            = 48
	execParentTGID     = 52
	execFlags          = 56
	execArgc           = 60
	execComm           = 64
	execParentComm     = 80
	execImageLen       = 96
	execFilenameLen    = 98
	execParentImageLen = 100
	execPathLen        = 102
	execArgsLen        = 104
	execArgsTotal      = 108

	snapSize        = 0
	snapFlags       = 4
	snapVisit       = 8
	snapStart       = 16
	snapParentStart = 24
	snapTGID        = 32
	snapParentTGID  = 36
	snapUID         = 40
	snapEUID        = 44
	snapGID         = 48
	snapThreads     = 52
	snapComm        = 56
	snapImageLen    = 72
	snapPathLen     = 74
	snapReserved    = 76
)

// Flag bits, mirror PW_F_* in bpf/pw.h.
const (
	fImageTrunc    = 1 << 0
	fFilenameTrunc = 1 << 1
	fPathTrunc     = 1 << 2
	fPathDeleted   = 1 << 3
	fPathErr       = 1 << 4
	fArgsCaptured  = 1 << 5
	fArgsTrunc     = 1 << 6
	fArgsErr       = 1 << 7
	fFromThread    = 1 << 8
	fImageErr      = 1 << 9
	fNoMM          = 1 << 10
	fFilenameErr   = 1 << 11
)

// Counter indexes, mirror enum pw_stat in bpf/pw.h.
const (
	statLostFork = iota
	statLostExec
	statLostExit
	statFork
	statExec
	statExit
	statThreadClone
	statKThread
	statThreadExit
	statLiveOOR
	statScratch
	statArgsErr
	statPathErr
	statMax
)

var le = binary.LittleEndian

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// decode parses one ring buffer record.
func decode(b []byte, lim collector.ArgLimits) (collector.Event, error) {
	if len(b) < hdrSize {
		return collector.Event{}, fmt.Errorf("record of %d bytes is shorter than the header", len(b))
	}
	switch t := le.Uint32(b[hdrType:]); t {
	case evFork:
		return decodeFork(b)
	case evExec:
		return decodeExec(b, lim)
	case evExit:
		return decodeExit(b)
	default:
		return collector.Event{}, fmt.Errorf("unknown record type %d", t)
	}
}

func decodeFork(b []byte) (collector.Event, error) {
	if len(b) < forkSize {
		return collector.Event{}, fmt.Errorf("fork record of %d bytes, want %d", len(b), forkSize)
	}
	return collector.Event{
		Kind:   collector.KindFork,
		BootNS: le.Uint64(b[hdrKtime:]),
		Proc: collector.Key{
			TGID:    le.Uint32(b[forkChildTGID:]),
			StartNS: le.Uint64(b[forkChildStart:]),
		},
		Parent: collector.Key{
			TGID:    le.Uint32(b[forkParentTGID:]),
			StartNS: le.Uint64(b[forkParentStart:]),
		},
		TID:  le.Uint32(b[forkParentTID:]),
		UID:  le.Uint32(b[forkUID:]),
		EUID: le.Uint32(b[forkEUID:]),
		GID:  le.Uint32(b[forkGID:]),
		Comm: cstr(b[forkComm : forkComm+16]),
	}, nil
}

func decodeExit(b []byte) (collector.Event, error) {
	if len(b) < exitSize {
		return collector.Event{}, fmt.Errorf("exit record of %d bytes, want %d", len(b), exitSize)
	}
	return collector.Event{
		Kind:       collector.KindExit,
		BootNS:     le.Uint64(b[hdrKtime:]),
		Proc:       collector.Key{TGID: le.Uint32(b[exitTGID:]), StartNS: le.Uint64(b[exitStart:])},
		TID:        le.Uint32(b[exitTID:]),
		ExitStatus: int32(le.Uint32(b[exitStatus:])),
	}, nil
}

func decodeExec(b []byte, lim collector.ArgLimits) (collector.Event, error) {
	if len(b) < execFixedSize {
		return collector.Event{}, fmt.Errorf("exec record of %d bytes, want at least %d", len(b), execFixedSize)
	}
	flags := le.Uint32(b[execFlags:])
	imageLen := int(le.Uint16(b[execImageLen:]))
	filenameLen := int(le.Uint16(b[execFilenameLen:]))
	parentImageLen := int(le.Uint16(b[execParentImageLen:]))
	pathLen := int(le.Uint16(b[execPathLen:]))
	argsLen := int(le.Uint32(b[execArgsLen:]))
	if total := execFixedSize + imageLen + filenameLen + parentImageLen + pathLen + argsLen; len(b) < total {
		return collector.Event{}, fmt.Errorf("exec record of %d bytes, lengths need %d", len(b), total)
	}
	data := b[execFixedSize:]
	take := func(n int) []byte {
		s := data[:n]
		data = data[n:]
		return s
	}
	image := take(imageLen)
	filename := take(filenameLen)
	parentImage := take(parentImageLen)
	path := take(pathLen)
	args := take(argsLen)

	ev := collector.Event{
		Kind:   collector.KindExec,
		BootNS: le.Uint64(b[hdrKtime:]),
		Proc:   collector.Key{TGID: le.Uint32(b[execTGID:]), StartNS: le.Uint64(b[execStart:])},
		Parent: collector.Key{
			TGID:    le.Uint32(b[execParentTGID:]),
			StartNS: le.Uint64(b[execParentStart:]),
		},
		TID:  le.Uint32(b[execTIDBefore:]),
		UID:  le.Uint32(b[execUID:]),
		EUID: le.Uint32(b[execEUID:]),
		GID:  le.Uint32(b[execGID:]),
		Comm: cstr(b[execComm : execComm+16]),
	}
	ev.Exec = collector.ExecInfo{
		Image:             string(image),
		ImageOK:           flags&fImageErr == 0,
		ImageTruncated:    flags&fImageTrunc != 0,
		Filename:          string(filename),
		FilenameOK:        flags&fFilenameErr == 0,
		FilenameTruncated: flags&fFilenameTrunc != 0,
		ParentComm:        cstr(b[execParentComm : execParentComm+16]),
		ParentImage:       string(parentImage),
		FromThread:        flags&fFromThread != 0,
		TIDBefore:         le.Uint32(b[execTIDBefore:]),
		Path: collector.Path{
			Value:     string(path),
			Known:     flags&fPathErr == 0 && pathLen > 0,
			Truncated: flags&fPathTrunc != 0,
			Deleted:   flags&fPathDeleted != 0,
		},
	}
	switch {
	case flags&fArgsCaptured == 0:
		ev.Exec.Args = collector.Args{State: collector.ArgsNotCaptured}
	case flags&fArgsErr != 0:
		ev.Exec.Args = collector.Args{State: collector.ArgsFailed, Argc: int(le.Uint32(b[execArgc:])), Limits: lim}
	default:
		ev.Exec.Args = collector.ParseArgs(args, flags&fArgsTrunc != 0, int(le.Uint32(b[execArgc:])), int(le.Uint32(b[execArgsTotal:])), lim)
	}
	return ev, nil
}

// decodeSnapshot reads the byte stream written by the task iterator: records
// back to back, each starting with its own total size.
func decodeSnapshot(r io.Reader) ([]collector.SnapProc, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var procs []collector.SnapProc
	var head [snapFixedSize]byte
	for {
		if _, err := io.ReadFull(br, head[:4]); err != nil {
			if errors.Is(err, io.EOF) {
				return procs, nil
			}
			return procs, fmt.Errorf("reading snapshot record size: %w", err)
		}
		size := int(le.Uint32(head[snapSize:]))
		if size < snapFixedSize || size > maxSnapRecord {
			return procs, fmt.Errorf("snapshot record size %d out of range", size)
		}
		rec := make([]byte, size)
		copy(rec, head[:4])
		if _, err := io.ReadFull(br, rec[4:]); err != nil {
			return procs, fmt.Errorf("reading snapshot record: %w", err)
		}
		p, err := decodeSnapProc(rec)
		if err != nil {
			return procs, err
		}
		procs = append(procs, p)
	}
}

func decodeSnapProc(b []byte) (collector.SnapProc, error) {
	flags := le.Uint32(b[snapFlags:])
	imageLen := int(le.Uint16(b[snapImageLen:]))
	pathLen := int(le.Uint16(b[snapPathLen:]))
	if snapFixedSize+imageLen+pathLen > len(b) {
		return collector.SnapProc{}, fmt.Errorf("snapshot record of %d bytes, lengths need %d", len(b), snapFixedSize+imageLen+pathLen)
	}
	data := b[snapFixedSize:]
	return collector.SnapProc{
		Key:     collector.Key{TGID: le.Uint32(b[snapTGID:]), StartNS: le.Uint64(b[snapStart:])},
		Parent:  collector.Key{TGID: le.Uint32(b[snapParentTGID:]), StartNS: le.Uint64(b[snapParentStart:])},
		VisitNS: le.Uint64(b[snapVisit:]),
		UID:     le.Uint32(b[snapUID:]),
		EUID:    le.Uint32(b[snapEUID:]),
		GID:     le.Uint32(b[snapGID:]),
		Threads: le.Uint32(b[snapThreads:]),
		Comm:    cstr(b[snapComm : snapComm+16]),
		Image:   string(data[:imageLen]),
		ImageOK: flags&(fImageErr|fNoMM) == 0 && imageLen > 0,
		NoMM:    flags&fNoMM != 0,
		Path: collector.Path{
			Value:     string(data[imageLen : imageLen+pathLen]),
			Known:     flags&fPathErr == 0 && pathLen > 0,
			Truncated: flags&fPathTrunc != 0,
			Deleted:   flags&fPathDeleted != 0,
		},
	}, nil
}
