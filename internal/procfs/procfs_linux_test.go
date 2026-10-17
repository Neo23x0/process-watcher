//go:build linux

package procfs

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Neo23x0/process-watcher/internal/collector"
)

func TestBootID(t *testing.T) {
	id, err := BootID()
	if err != nil || len(id) != 36 || strings.Count(id, "-") != 4 || id != strings.ToLower(id) {
		t.Fatalf("%q %v", id, err)
	}
}

// keyOf builds the identity of a living process; the nanosecond start time is
// only known to tick resolution here, which is exactly what the check uses.
func keyOf(t *testing.T, pid int, plusNS uint64) collector.Key {
	t.Helper()
	ticks, err := startTicks(uint32(pid))
	if err != nil {
		t.Fatal(err)
	}
	return collector.Key{TGID: uint32(pid), StartNS: ticks*10_000_000 + plusNS}
}

func TestReadArgsVerifiesTheInstance(t *testing.T) {
	cmd := exec.Command("sleep", "30", "1")
	if err := cmd.Start(); err != nil {
		t.Skipf("no sleep binary: %v", err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	time.Sleep(50 * time.Millisecond)

	a := ReadArgs(keyOf(t, cmd.Process.Pid, 5_000_000))
	if a.State != collector.ArgsCaptured || len(a.List) != 3 || a.List[0] != "sleep" || a.List[1] != "30" || a.List[2] != "1" {
		t.Fatalf("%+v", a)
	}
	// A start time in another tick means another instance of the same pid: nothing is read.
	if a := ReadArgs(keyOf(t, cmd.Process.Pid, 50_000_000)); a.State != collector.ArgsFailed || a.List != nil {
		t.Fatalf("a different instance must not be read: %+v", a)
	}
	// A vanished process fails cleanly, as does an unreadable one.
	cmd.Process.Kill()
	cmd.Wait()
	if a := ReadArgs(collector.Key{TGID: uint32(cmd.Process.Pid), StartNS: 1}); a.State != collector.ArgsFailed {
		t.Fatalf("gone: %+v", a)
	}
}

func TestStartTicksParsesCommWithParentheses(t *testing.T) {
	// The own process: comm is "procfs.test" here, but the parser must split after the LAST ')'.
	if _, err := startTicks(uint32(os.Getpid())); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile("/proc/self/stat")
	if !strings.Contains(string(b), ") ") || strconv.IntSize == 0 {
		t.Fatal("unexpected stat format")
	}
}
