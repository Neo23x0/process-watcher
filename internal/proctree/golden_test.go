package proctree

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/Neo23x0/process-watcher/internal/collector"
	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/schemacheck"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/golden")

// golden compares one serialized event with testdata/golden/<name>. The golden
// files are the binding examples of the JSONL contract; they are validated
// against the JSON Schema as well.
func golden(t *testing.T, name string, ev *event.Event) {
	t.Helper()
	line, err := ev.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	if err := schemacheck.Validate(line); err != nil {
		t.Fatalf("golden event %s violates the schema: %v\n%s", name, err, line)
	}
	path := filepath.Join("..", "..", "testdata", "golden", name)
	if *update {
		if err := os.WriteFile(path, line, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run `go test ./internal/proctree -update` to create it)", err)
	}
	if !bytes.Equal(line, want) {
		t.Errorf("%s differs from the golden file.\n got: %s want: %s\nIf the change is intended run `go test ./internal/proctree -update` and review the diff.", name, line, want)
	}
}

// TestGoldenExecOfADescendant is the documented example scenario: a shell below
// an nginx root, started as "sh" (a symlink) although the program is dash.
func TestGoldenExecOfADescendant(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.CaptureArgv = true })
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, shell, 9_000_000_000_001))
	ex := execEv(shell, master, 9_000_123_456_789, "dash", "/usr/bin/dash", "sh", "-c", "id")
	ex.Comm = "sh"
	ex.Exec.Filename = "/bin/sh"
	h.handle(ex)
	ev := h.last()
	ev.Sequence = 42
	ev.EventID = "72c89dca-44f1-4224-9ab6-9cb77081a756"
	golden(t, "process_exec_descendant.jsonl", ev)
}

func TestGoldenForkDiscoveredAndExit(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.CaptureArgv = true })
	snap := snapshot(10_000_000_000_000, 10_000_000_100_000,
		snapProc(key(1, 1), key(0, 0), 10_000_000_000_001, "systemd", "/usr/lib/systemd/systemd"),
		snapProc(master, key(1, 1), 10_000_000_000_003, "nginx", "/usr/sbin/nginx"))
	h.apply(snap, nil, DiscoveryStartup)
	disc := h.last()
	disc.Sequence, disc.EventID = 3, "00000000-0000-4000-8000-0000000000d1"
	golden(t, "process_discovered_root.jsonl", disc)

	h.handle(forkEv(master, shell, 11_000_000_000_001))
	fork := h.last()
	fork.Sequence, fork.EventID = 4, "00000000-0000-4000-8000-0000000000f1"
	golden(t, "process_fork_descendant.jsonl", fork)

	h.handle(exitEv(shell, 11_500_000_000_000, 9)) // killed by SIGKILL
	exit := h.last()
	exit.Sequence, exit.EventID = 5, "00000000-0000-4000-8000-0000000000e1"
	golden(t, "process_exit_signal.jsonl", exit)
}

func TestGoldenKillRequested(t *testing.T) {
	h := killHarness(t, rules(t, []string{"image"}, nil, []string{`^(useradd|usermod)$`}))
	h.startNginx(master, 8_000_000_000_001)
	h.handle(forkEv(master, shell, 9_000_000_000_001), execEv(shell, master, 9_000_000_000_002, "useradd", "/usr/sbin/useradd", "useradd", "bob"))
	req := h.rec.ofType(event.TypeKillRequested)[0]
	req.Sequence = 7
	d := req.Details.(*event.KillDetails)
	d.ActionID = "00000000-0000-4000-8000-0000000000a1"
	req.EventID = "00000000-0000-4000-8000-0000000000a2"
	golden(t, "response_kill_requested.jsonl", req)
	_ = collector.Key{}
}
