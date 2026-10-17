//go:build linux

package ebpf

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The test binary doubles as the controlled process under test: when
// PW_HELPER is set, TestMain runs the named scenario instead of the tests, so
// the harness needs no shell helpers and a single static binary is enough for
// the VM runs.
func TestMain(m *testing.M) {
	if mode := os.Getenv("PW_HELPER"); mode != "" {
		helperMain(mode, os.Args[1:])
		return
	}
	os.Exit(m.Run())
}

// startHelper runs a scenario as a child of the test and returns its pid and
// the lines it printed once it exited. Lines look like "child=1234".
func startHelper(t *testing.T, mode string, args ...string) (pid uint32, out map[string]string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "PW_HELPER="+mode)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid = uint32(cmd.Process.Pid)
	out = map[string]string{}
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			out[k] = v
		}
	}
	if err := cmd.Wait(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatal(err)
		}
	}
	return pid, out
}

func outPID(t *testing.T, out map[string]string, key string) uint32 {
	t.Helper()
	n, err := strconv.ParseUint(out[key], 10, 32)
	if err != nil {
		t.Fatalf("helper did not report %q: %v (got %v)", key, err, out)
	}
	return uint32(n)
}

func say(k string, v any) { fmt.Printf("%s=%v\n", k, v) }

func helperMain(mode string, args []string) {
	switch mode {
	case "noop":
	case "true-child": // fork+exec a short-lived child
		cmd := exec.Command("/bin/true", args...)
		must(cmd.Run())
		say("child", cmd.ProcessState.Pid())
	case "fork-noexec": // fork without exec; the child exits with status 7
		say("child", rawFork(func() { unix.RawSyscall(unix.SYS_EXIT_GROUP, 7, 0, 0) }))
	case "clone3-noexec":
		say("child", rawClone3(func() { unix.RawSyscall(unix.SYS_EXIT_GROUP, 9, 0, 0) }))
	case "double-fork": // child forks a grandchild that outlives it
		pid := rawFork(func() {
			rawFork(func() { rawSleep(300 * time.Millisecond) })
			// the child exits right away; the grandchild is reparented
		})
		say("child", pid)
		time.Sleep(600 * time.Millisecond)
	case "thread-fork": // fork from a non-leader thread
		done := make(chan struct{})
		go onNonLeaderThread(func() {
			cmd := exec.Command("/bin/true")
			must(cmd.Run())
			say("child", cmd.ProcessState.Pid())
			say("forking-tid", unix.Gettid())
			say("threads", threadIDs())
		}, done)
		<-done
	case "thread-exec": // exec from a non-leader thread: it takes over the leader's identity
		done := make(chan struct{})
		go onNonLeaderThread(func() {
			say("exec-tid", unix.Gettid())
			os.Stdout.Sync()
			must(syscall.Exec("/bin/true", []string{"true-from-thread"}, os.Environ()))
		}, done)
		<-done
	case "leader-exit": // the thread group leader exits while another thread keeps the process alive
		runtime.LockOSThread()
		go func() {
			time.Sleep(400 * time.Millisecond)
			os.Exit(3)
		}()
		time.Sleep(50 * time.Millisecond)
		say("leader-tid", unix.Gettid())
		os.Stdout.Sync()
		unix.RawSyscall(unix.SYS_EXIT, 0, 0, 0) // ends only this thread
	case "exec-chain": // several successful execs in one process instance
		n, _ := strconv.Atoi(args[0])
		if n > 0 {
			must(syscall.Exec(os.Args[0], []string{os.Args[0], strconv.Itoa(n - 1)}, os.Environ()))
		}
	case "exec-fail":
		err := syscall.Exec("/nonexistent/binary", []string{"x"}, os.Environ())
		say("exec-error", err)
		// not executable: ENOEXEC/EACCES style failure after a successful lookup
		err = syscall.Exec("/etc/passwd", []string{"x"}, os.Environ())
		say("exec-error2", err)
		must(exec.Command("/bin/true").Run()) // the failures above must not have produced records
	case "symlink-exec": // the program is called through a symlink with another name
		dir := args[0]
		link := filepath.Join(dir, "sh-link")
		must(os.Symlink("/bin/true", link))
		must(syscall.Exec(link, []string{"sh", "-c", "id"}, os.Environ()))
	case "script-exec":
		must(syscall.Exec(args[0], []string{args[0], "script-arg"}, os.Environ()))
	case "memfd-exec": // fileless execution
		data, err := os.ReadFile("/bin/true")
		must(err)
		fd, err := unix.MemfdCreate("pw-test", unix.MFD_CLOEXEC)
		must(err)
		_, err = unix.Write(fd, data)
		must(err)
		must(execveatFD(fd, []string{"memfd-prog"}))
	case "deleted-exec": // execute a file that was unlinked before the exec
		data, err := os.ReadFile("/bin/true")
		must(err)
		p := args[0]
		must(os.WriteFile(p, data, 0o700))
		fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		must(err)
		must(os.Remove(p))
		must(execveatFD(fd, []string{"deleted-prog"}))
	case "deep-exec": // path deeper than the walker follows
		p := args[0]
		must(os.MkdirAll(p, 0o700))
		data, err := os.ReadFile("/bin/true")
		must(err)
		bin := filepath.Join(p, "deep-prog")
		must(os.WriteFile(bin, data, 0o700))
		must(unix.Chdir(p)) // run via a relative name: the walker sees the full path anyway
		must(syscall.Exec("./deep-prog", []string{"deep-prog"}, os.Environ()))
	case "many-args":
		n, _ := strconv.Atoi(args[0])
		size, _ := strconv.Atoi(args[1])
		argv := []string{"/bin/true"}
		for i := 0; i < n; i++ {
			argv = append(argv, strings.Repeat("x", size))
		}
		must(syscall.Exec("/bin/true", argv, os.Environ()))
	case "burst": // n short lived children without waiting in between
		n, _ := strconv.Atoi(args[0])
		for i := 0; i < n; i++ {
			c := exec.Command("/bin/true")
			must(c.Start())
			go c.Wait()
		}
		time.Sleep(500 * time.Millisecond)
	default:
		fmt.Fprintln(os.Stderr, "unknown helper mode", mode)
		os.Exit(2)
	}
	os.Stdout.Sync()
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		os.Exit(99)
	}
}

// onNonLeaderThread runs f on an OS thread that is not the thread group
// leader and closes done afterwards.
func onNonLeaderThread(f func(), done chan struct{}) {
	for {
		ready := make(chan bool)
		go func() {
			runtime.LockOSThread()
			if unix.Gettid() == os.Getpid() {
				runtime.UnlockOSThread()
				ready <- false
				return // this goroutine ran on the leader thread; try another one
			}
			ready <- true
			f()
			close(done)
		}()
		if <-ready {
			return
		}
	}
}

// rawFork is a plain fork(2) without exec. The child must only run
// async-signal-safe code (raw system calls), because the Go runtime is not
// usable in a forked child.
func rawFork(child func()) int {
	pid, _, errno := unix.RawSyscall(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0)
	if errno != 0 {
		must(errno)
	}
	if pid == 0 {
		child()
		unix.RawSyscall(unix.SYS_EXIT_GROUP, 0, 0, 0)
	}
	return int(pid)
}

// rawSleep sleeps without touching the Go runtime (for use after a raw fork).
func rawSleep(d time.Duration) {
	ts := unix.NsecToTimespec(int64(d))
	unix.RawSyscall(unix.SYS_NANOSLEEP, uintptr(unsafe.Pointer(&ts)), 0, 0)
}

func rawClone3(child func()) int {
	args := cloneArgs{ExitSignal: uint64(unix.SIGCHLD)}
	pid, _, errno := unix.RawSyscall(unix.SYS_CLONE3, uintptr(unsafe.Pointer(&args)), unsafe.Sizeof(args), 0)
	if errno != 0 {
		must(errno)
	}
	if pid == 0 {
		child()
		unix.RawSyscall(unix.SYS_EXIT_GROUP, 0, 0, 0)
	}
	return int(pid)
}

// execveatFD runs the file behind fd (AT_EMPTY_PATH), like fexecve(3).
func execveatFD(fd int, argv []string) error {
	path, _ := unix.BytePtrFromString("")
	a, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return err
	}
	e, err := syscall.SlicePtrFromStrings(os.Environ())
	if err != nil {
		return err
	}
	_, _, errno := unix.Syscall6(unix.SYS_EXECVEAT, uintptr(fd), uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(&a[0])), uintptr(unsafe.Pointer(&e[0])), unix.AT_EMPTY_PATH, 0)
	return errno
}

// cloneArgs is struct clone_args (CLONE_ARGS_SIZE_VER0).
type cloneArgs struct {
	Flags, Pidfd, ChildTid, ParentTid, ExitSignal, Stack, StackSize, Tls uint64
}

// threadIDs lists the thread ids of this process, comma separated.
func threadIDs() string {
	ents, _ := os.ReadDir("/proc/self/task")
	var ids []string
	for _, e := range ents {
		ids = append(ids, e.Name())
	}
	return strings.Join(ids, ",")
}
