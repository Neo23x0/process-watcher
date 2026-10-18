package ebpf

import (
	"bytes"
	_ "embed"
	"reflect"
	"testing"
	"testing/iotest"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/Neo23x0/process-watcher/internal/collector"
)

//go:embed pw_bpfel.o
var objBytes []byte

// TestWireContract compares the Go side offsets, sizes and enum values with the
// BTF of the embedded object, which is compiled from bpf/pw.h.
func TestWireContract(t *testing.T) {
	spec, err := cebpf.LoadCollectionSpecFromReader(bytes.NewReader(objBytes))
	if err != nil {
		t.Fatalf("load embedded object: %v", err)
	}

	structs := map[string]struct {
		size    uint32
		offsets map[string]int
	}{
		"pw_hdr": {hdrSize, map[string]int{"type": hdrType, "size": hdrSizeF, "ktime_ns": hdrKtime}},
		"pw_fork": {forkSize, map[string]int{
			"h": 0, "parent_start_ns": forkParentStart, "child_start_ns": forkChildStart,
			"parent_tgid": forkParentTGID, "parent_tid": forkParentTID, "child_tgid": forkChildTGID,
			"uid": forkUID, "euid": forkEUID, "gid": forkGID, "comm": forkComm,
		}},
		"pw_exit": {exitSize, map[string]int{
			"h": 0, "start_ns": exitStart, "tgid": exitTGID, "tid": exitTID, "status": exitStatus, "flags": exitFlags,
		}},
		"pw_exec": {execFixedSize, map[string]int{
			"h": 0, "start_ns": execStart, "parent_start_ns": execParentStart, "tgid": execTGID,
			"tid_before": execTIDBefore, "uid": execUID, "euid": execEUID, "gid": execGID,
			"parent_tgid": execParentTGID, "flags": execFlags, "argc": execArgc, "comm": execComm,
			"parent_comm": execParentComm, "image_len": execImageLen, "filename_len": execFilenameLen,
			"parent_image_len": execParentImageLen, "path_len": execPathLen, "args_len": execArgsLen,
			"args_total": execArgsTotal,
		}},
		"pw_snap": {snapFixedSize, map[string]int{
			"size": snapSize, "flags": snapFlags, "visit_ns": snapVisit, "start_ns": snapStart,
			"parent_start_ns": snapParentStart, "tgid": snapTGID, "parent_tgid": snapParentTGID,
			"uid": snapUID, "euid": snapEUID, "gid": snapGID, "live_threads": snapThreads,
			"comm": snapComm, "image_len": snapImageLen, "path_len": snapPathLen, "reserved": snapReserved,
		}},
	}
	for name, want := range structs {
		var st *btf.Struct
		if err := spec.Types.TypeByName(name, &st); err != nil {
			t.Errorf("struct %s not in BTF: %v", name, err)
			continue
		}
		if st.Size != want.size {
			t.Errorf("struct %s: size %d, Go expects %d", name, st.Size, want.size)
		}
		if len(st.Members) != len(want.offsets) {
			t.Errorf("struct %s: %d members in C, %d known to Go", name, len(st.Members), len(want.offsets))
		}
		for _, m := range st.Members {
			off, ok := want.offsets[m.Name]
			if !ok {
				t.Errorf("struct %s: member %q unknown to Go", name, m.Name)
				continue
			}
			if got := int(m.Offset.Bytes()); got != off {
				t.Errorf("struct %s: member %s at %d, Go expects %d", name, m.Name, got, off)
			}
		}
	}

	enums := map[string]map[string]uint64{
		"pw_event_type": {"PW_EV_FORK": uint64(evFork), "PW_EV_EXEC": uint64(evExec), "PW_EV_EXIT": uint64(evExit)},
		"pw_stat": {
			"PW_STAT_LOST_FORK": statLostFork, "PW_STAT_LOST_EXEC": statLostExec, "PW_STAT_LOST_EXIT": statLostExit,
			"PW_STAT_FORK": statFork, "PW_STAT_EXEC": statExec, "PW_STAT_EXIT": statExit,
			"PW_STAT_THREAD_CLONE": statThreadClone, "PW_STAT_KTHREAD": statKThread,
			"PW_STAT_THREAD_EXIT": statThreadExit, "PW_STAT_LIVE_OOR": statLiveOOR,
			"PW_STAT_SCRATCH": statScratch, "PW_STAT_ARGS_ERR": statArgsErr,
			"PW_STAT_PATH_ERR": statPathErr, "PW_STAT_MAX": statMax,
		},
	}
	for name, want := range enums {
		var e *btf.Enum
		if err := spec.Types.TypeByName(name, &e); err != nil {
			t.Errorf("enum %s not in BTF: %v", name, err)
			continue
		}
		if len(e.Values) != len(want) {
			t.Errorf("enum %s: %d values in C, %d known to Go", name, len(e.Values), len(want))
		}
		for _, v := range e.Values {
			if w, ok := want[v.Name]; !ok || w != v.Value {
				t.Errorf("enum %s: %s = %d, Go expects %d (known=%v)", name, v.Name, v.Value, w, ok)
			}
		}
	}

	for _, name := range []string{"pw_events", "pw_stats", "pw_live"} {
		if _, ok := spec.Maps[name]; !ok {
			t.Errorf("map %s missing in the object", name)
		}
	}
	for _, name := range []string{"pw_sched_process_fork", "pw_sched_process_exec", "pw_sched_process_exit", "pw_dump_task"} {
		if _, ok := spec.Programs[name]; !ok {
			t.Errorf("program %s missing in the object", name)
		}
	}
}

func put32(b []byte, off int, v uint32) { le.PutUint32(b[off:], v) }
func put64(b []byte, off int, v uint64) { le.PutUint64(b[off:], v) }
func put16(b []byte, off int, v uint16) { le.PutUint16(b[off:], v) }

func TestDecodeFork(t *testing.T) {
	b := make([]byte, forkSize)
	put32(b, hdrType, evFork)
	put32(b, hdrSizeF, forkSize)
	put64(b, hdrKtime, 777)
	put64(b, forkParentStart, 10)
	put64(b, forkChildStart, 20)
	put32(b, forkParentTGID, 100)
	put32(b, forkParentTID, 101)
	put32(b, forkChildTGID, 200)
	put32(b, forkUID, 33)
	put32(b, forkEUID, 34)
	put32(b, forkGID, 35)
	copy(b[forkComm:], "nginx\x00junk")

	ev, err := decode(b, collector.ArgLimits{})
	if err != nil {
		t.Fatal(err)
	}
	want := collector.Event{
		Kind: collector.KindFork, BootNS: 777,
		Proc:   collector.Key{TGID: 200, StartNS: 20},
		Parent: collector.Key{TGID: 100, StartNS: 10},
		TID:    101, UID: 33, EUID: 34, GID: 35, Comm: "nginx",
	}
	if !reflect.DeepEqual(ev, want) {
		t.Fatalf("got %+v\nwant %+v", ev, want)
	}
}

func TestDecodeExit(t *testing.T) {
	b := make([]byte, exitSize)
	put32(b, hdrType, evExit)
	put64(b, hdrKtime, 99)
	put64(b, exitStart, 5)
	put32(b, exitTGID, 7)
	put32(b, exitTID, 8)
	put32(b, exitStatus, uint32(0x100)) // exit(1)
	ev, err := decode(b, collector.ArgLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != collector.KindExit || ev.Proc != (collector.Key{TGID: 7, StartNS: 5}) || ev.TID != 8 || ev.ExitStatus != 0x100 || ev.BootNS != 99 {
		t.Fatalf("unexpected exit event %+v", ev)
	}
}

func execRecord(flags uint32, image, filename, parentImage, path string, args []byte, argc uint32) []byte {
	b := make([]byte, execFixedSize, execFixedSize+len(image)+len(filename)+len(parentImage)+len(path)+len(args))
	put32(b, hdrType, evExec)
	put64(b, hdrKtime, 4242)
	put64(b, execStart, 1)
	put64(b, execParentStart, 2)
	put32(b, execTGID, 1235)
	put32(b, execTIDBefore, 1236)
	put32(b, execUID, 33)
	put32(b, execEUID, 33)
	put32(b, execGID, 33)
	put32(b, execParentTGID, 1200)
	put32(b, execFlags, flags)
	put32(b, execArgc, argc)
	copy(b[execComm:], "sh")
	copy(b[execParentComm:], "nginx")
	put16(b, execImageLen, uint16(len(image)))
	put16(b, execFilenameLen, uint16(len(filename)))
	put16(b, execParentImageLen, uint16(len(parentImage)))
	put16(b, execPathLen, uint16(len(path)))
	put32(b, execArgsLen, uint32(len(args)))
	b = append(b, image...)
	b = append(b, filename...)
	b = append(b, parentImage...)
	b = append(b, path...)
	b = append(b, args...)
	put32(b, hdrSizeF, uint32(len(b)))
	return b
}

func TestDecodeExecSymlinkAndArgs(t *testing.T) {
	// The shell was started as "sh" (requested filename /bin/sh), the executed
	// file is dash: image must be dash, not argv[0].
	rec := execRecord(fArgsCaptured|fFromThread, "dash", "/bin/sh", "nginx", "/usr/bin/dash",
		[]byte("sh\x00-c\x00id\x00"), 3)
	ev, err := decode(rec, collector.ArgLimits{})
	if err != nil {
		t.Fatal(err)
	}
	x := ev.Exec
	if x.Image != "dash" || !x.ImageOK || x.Filename != "/bin/sh" || x.ParentImage != "nginx" || x.ParentComm != "nginx" {
		t.Fatalf("unexpected strings %+v", x)
	}
	if x.Path != (collector.Path{Value: "/usr/bin/dash", Known: true}) {
		t.Fatalf("unexpected path %+v", x.Path)
	}
	if !x.FromThread || x.TIDBefore != 1236 {
		t.Fatalf("thread exec not decoded: %+v", x)
	}
	if x.Args.State != collector.ArgsCaptured || len(x.Args.List) != 3 || x.Args.List[1] != "-c" || x.Args.Truncated {
		t.Fatalf("unexpected args %+v", x.Args)
	}
	if ev.Comm != "sh" || ev.Proc != (collector.Key{TGID: 1235, StartNS: 1}) || ev.Parent.TGID != 1200 {
		t.Fatalf("unexpected header fields %+v", ev)
	}
}

func TestDecodeExecFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags uint32
		path  string
		args  []byte
		check func(t *testing.T, x collector.ExecInfo)
	}{
		{"args not captured", 0, "/bin/x", nil, func(t *testing.T, x collector.ExecInfo) {
			if x.Args.State != collector.ArgsNotCaptured || x.Args.List != nil {
				t.Fatalf("%+v", x.Args)
			}
		}},
		{"args read failed", fArgsCaptured | fArgsErr, "/bin/x", nil, func(t *testing.T, x collector.ExecInfo) {
			if x.Args.State != collector.ArgsFailed {
				t.Fatalf("%+v", x.Args)
			}
		}},
		{"raw args cut", fArgsCaptured | fArgsTrunc, "/bin/x", []byte("a\x00bb\x00cc"), func(t *testing.T, x collector.ExecInfo) {
			if !x.Args.Truncated || len(x.Args.List) != 2 {
				t.Fatalf("partial argument must be dropped: %+v", x.Args)
			}
		}},
		{"path error", fPathErr, "", nil, func(t *testing.T, x collector.ExecInfo) {
			if x.Path.Known {
				t.Fatalf("%+v", x.Path)
			}
		}},
		{"path truncated and deleted", fPathTrunc | fPathDeleted, "/x/y", nil, func(t *testing.T, x collector.ExecInfo) {
			if !x.Path.Truncated || !x.Path.Deleted || !x.Path.Known {
				t.Fatalf("%+v", x.Path)
			}
		}},
		{"image and filename flags", fImageTrunc | fFilenameTrunc | fFilenameErr, "/x", nil, func(t *testing.T, x collector.ExecInfo) {
			if !x.ImageTruncated || !x.FilenameTruncated || x.FilenameOK {
				t.Fatalf("%+v", x)
			}
		}},
		{"image unreadable", fImageErr, "/x", nil, func(t *testing.T, x collector.ExecInfo) {
			if x.ImageOK {
				t.Fatalf("%+v", x)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := decode(execRecord(tc.flags, "img", "fn", "pimg", tc.path, tc.args, 0), collector.ArgLimits{})
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, ev.Exec)
		})
	}
}

func TestDecodeRejectsBrokenRecords(t *testing.T) {
	good := execRecord(0, "dash", "/bin/sh", "nginx", "/usr/bin/dash", nil, 0)
	for name, b := range map[string][]byte{
		"empty":            nil,
		"short header":     make([]byte, 8),
		"unknown type":     append([]byte{9, 0, 0, 0}, make([]byte, 40)...),
		"short fork":       append([]byte{1, 0, 0, 0}, make([]byte, 20)...),
		"short exit":       append([]byte{3, 0, 0, 0}, make([]byte, 20)...),
		"short exec fixed": good[:execFixedSize-1],
		"exec lengths lie": good[:len(good)-3],
	} {
		if _, err := decode(b, collector.ArgLimits{}); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func snapRecord(tgid uint32, image, path string, flags uint32) []byte {
	b := make([]byte, snapFixedSize)
	put32(b, snapFlags, flags)
	put64(b, snapVisit, 900)
	put64(b, snapStart, 50)
	put64(b, snapParentStart, 40)
	put32(b, snapTGID, tgid)
	put32(b, snapParentTGID, 1)
	put32(b, snapUID, 1000)
	put32(b, snapThreads, 3)
	copy(b[snapComm:], "comm")
	put16(b, snapImageLen, uint16(len(image)))
	put16(b, snapPathLen, uint16(len(path)))
	b = append(b, image...)
	b = append(b, path...)
	put32(b, snapSize, uint32(len(b)))
	return b
}

func TestDecodeSnapshotStream(t *testing.T) {
	var stream []byte
	stream = append(stream, snapRecord(10, "nginx", "/usr/sbin/nginx", 0)...)
	stream = append(stream, snapRecord(11, "", "", fNoMM)...)
	stream = append(stream, snapRecord(12, "bash", "/bin/bash", fPathDeleted)...)

	// One byte at a time proves that records may be split across read calls.
	procs, err := decodeSnapshot(iotest.OneByteReader(bytes.NewReader(stream)))
	if err != nil {
		t.Fatal(err)
	}
	if len(procs) != 3 {
		t.Fatalf("got %d records", len(procs))
	}
	if p := procs[0]; p.Key != (collector.Key{TGID: 10, StartNS: 50}) || p.Image != "nginx" || !p.ImageOK ||
		p.Path.Value != "/usr/sbin/nginx" || !p.Path.Known || p.VisitNS != 900 || p.Comm != "comm" ||
		p.Parent != (collector.Key{TGID: 1, StartNS: 40}) || p.Threads != 3 || p.UID != 1000 {
		t.Fatalf("unexpected first record %+v", p)
	}
	if p := procs[1]; !p.NoMM || p.ImageOK {
		t.Fatalf("zombie leader must be flagged: %+v", p)
	}
	if p := procs[2]; !p.Path.Deleted {
		t.Fatalf("deleted flag lost: %+v", p)
	}
}

func TestDecodeSnapshotErrors(t *testing.T) {
	good := snapRecord(10, "nginx", "/usr/sbin/nginx", 0)
	if _, err := decodeSnapshot(bytes.NewReader(good[:len(good)-2])); err == nil {
		t.Error("truncated record: want an error")
	}
	bad := append([]byte(nil), good...)
	put32(bad, snapSize, 3)
	if _, err := decodeSnapshot(bytes.NewReader(bad)); err == nil {
		t.Error("size below fixed part: want an error")
	}
	if procs, err := decodeSnapshot(bytes.NewReader(nil)); err != nil || len(procs) != 0 {
		t.Errorf("empty stream: %v %v", procs, err)
	}
}
