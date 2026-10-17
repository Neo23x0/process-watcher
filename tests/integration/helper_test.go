//go:build linux

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// recipe describes a small process tree. Every node is the test binary
// started under the node's name; children are started from the node and write
// to the same stdout, so the test sees one line per process.
type recipe struct {
	Name     string   `json:"name"`
	Mode     string   `json:"mode,omitempty"` // helper mode; "node" by default
	Args     []string `json:"args,omitempty"`
	Children []recipe `json:"children,omitempty"`
	DelayMS  int      `json:"delay_ms,omitempty"` // pause before each child is started
	// Action after the children were started: "wait" (default), "sleep:<ms>",
	// "leave" (exit at once, the children become orphans).
	Action string `json:"action,omitempty"`
}

func (r recipe) json() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func say(format string, a ...any) { fmt.Printf(format+"\n", a...) }

func baseName() string { return filepath.Base(os.Args[0]) }

func helperMain(mode string, args []string) {
	switch mode {
	case "node":
		nodeMain()
	case "sleep": // a process that just waits
		d := 60 * time.Second
		if len(args) > 0 {
			if ms, err := strconv.Atoi(args[0]); err == nil {
				d = time.Duration(ms) * time.Millisecond
			}
		}
		say("up pid=%d name=%s ppid=%d", os.Getpid(), baseName(), os.Getppid())
		time.Sleep(d)
	case "exit": // exits at once (a short lived process such as useradd)
		say("up pid=%d name=%s ppid=%d", os.Getpid(), baseName(), os.Getppid())
	case "burst": // n short lived children, one after the other
		n, _ := strconv.Atoi(args[0])
		say("up pid=%d name=%s ppid=%d", os.Getpid(), baseName(), os.Getppid())
		for i := 0; i < n; i++ {
			c := exec.Command("/bin/true")
			if err := c.Run(); err != nil {
				fmt.Fprintln(os.Stderr, "burst:", err)
				os.Exit(1)
			}
			say("child pid=%d", c.ProcessState.Pid())
		}
		say("done n=%d", n)
	case "fork-noexec":
		say("up pid=%d name=%s ppid=%d", os.Getpid(), baseName(), os.Getppid())
		pid, _, errno := unix.RawSyscall(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0)
		if errno != 0 {
			fmt.Fprintln(os.Stderr, "clone:", errno)
			os.Exit(1)
		}
		if pid == 0 {
			unix.RawSyscall(unix.SYS_EXIT_GROUP, 7, 0, 0)
		}
		var ws syscall.WaitStatus
		syscall.Wait4(int(pid), &ws, 0, nil)
		say("child pid=%d exit=%d", pid, ws.ExitStatus())
	case "exec-chain": // successive execs of different file names in one process
		names := args
		say("up pid=%d name=%s ppid=%d", os.Getpid(), baseName(), os.Getppid())
		if len(names) == 0 {
			return
		}
		next := filepath.Join(os.Getenv("PW_E2E_DIR"), names[0])
		if err := syscall.Exec(next, append([]string{names[0]}, names[1:]...), os.Environ()); err != nil {
			fmt.Fprintln(os.Stderr, "exec:", err)
			os.Exit(1)
		}
	case "exec-fail":
		say("up pid=%d name=%s ppid=%d", os.Getpid(), baseName(), os.Getppid())
		e1 := syscall.Exec("/nonexistent/binary", []string{"x"}, os.Environ())
		e2 := syscall.Exec("/etc/passwd", []string{"x"}, os.Environ())
		say("failed e1=%v e2=%v", e1 != nil, e2 != nil)
		c := exec.Command("/bin/true")
		_ = c.Run()
		say("child pid=%d", c.ProcessState.Pid())
	case "fork-then-exec": // starts a child, then execs into another program name
		say("up pid=%d name=%s ppid=%d", os.Getpid(), baseName(), os.Getppid())
		dir := os.Getenv("PW_E2E_DIR")
		child := exec.Command(filepath.Join(dir, args[0]), "30000")
		child.Env = withEnv(os.Environ(), "PW_E2E_HELPER", "sleep")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "start child:", err)
			os.Exit(1)
		}
		say("child pid=%d name=%s", child.Process.Pid, args[0])
		time.Sleep(300 * time.Millisecond)
		env := withEnv(os.Environ(), "PW_E2E_HELPER", "sleep")
		if err := syscall.Exec(filepath.Join(dir, args[1]), []string{args[1], "20000"}, env); err != nil {
			fmt.Fprintln(os.Stderr, "exec:", err)
			os.Exit(1)
		}
	case "args-special": // arguments with a newline, a quote and invalid UTF-8
		say("up pid=%d name=%s ppid=%d", os.Getpid(), baseName(), os.Getppid())
		c := exec.Command("/bin/true", "line1\nline2", `say "hi" <b>&</b>`, "bad\xff\xfebytes", "tab\there")
		_ = c.Run()
		say("child pid=%d", c.ProcessState.Pid())
	default:
		if f, ok := extraHelpers[mode]; ok {
			f(args)
			return
		}
		fmt.Fprintln(os.Stderr, "unknown helper mode", mode)
		os.Exit(2)
	}
}

// withEnv returns env with key set to value and no duplicate of key: a raw
// execve passes duplicates on, and the new process would read the first one.
func withEnv(env []string, key, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, e := range env {
		if !strings.HasPrefix(e, key+"=") {
			out = append(out, e)
		}
	}
	return append(out, key+"="+value)
}

// extraHelpers lets other test files register additional helper modes from an
// init function without touching this file.
var extraHelpers = map[string]func(args []string){}

func nodeMain() {
	var r recipe
	if err := json.Unmarshal([]byte(os.Getenv("PW_E2E_RECIPE")), &r); err != nil {
		fmt.Fprintln(os.Stderr, "bad recipe:", err)
		os.Exit(2)
	}
	say("up pid=%d name=%s ppid=%d", os.Getpid(), baseName(), os.Getppid())

	var wg sync.WaitGroup
	for _, ch := range r.Children {
		if r.DelayMS > 0 {
			time.Sleep(time.Duration(r.DelayMS) * time.Millisecond)
		}
		mode := ch.Mode
		if mode == "" {
			mode = "node"
		}
		cmd := exec.Command(filepath.Join(os.Getenv("PW_E2E_DIR"), ch.Name), ch.Args...)
		cmd.Env = append(os.Environ(), "PW_E2E_HELPER="+mode, "PW_E2E_RECIPE="+ch.json())
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			say("spawn-failed name=%s err=%q", ch.Name, err.Error())
			continue
		}
		pid := cmd.Process.Pid
		say("spawned name=%s pid=%d by=%d", ch.Name, pid, os.Getpid())
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			err := cmd.Wait()
			ws, _ := cmd.ProcessState.Sys().(syscall.WaitStatus)
			switch {
			case ws.Signaled():
				say("child-ended name=%s pid=%d signal=%d", name, pid, int(ws.Signal()))
			default:
				say("child-ended name=%s pid=%d exit=%d", name, pid, ws.ExitStatus())
			}
			_ = err
		}(ch.Name)
	}

	action := r.Action
	switch {
	case action == "leave":
		return
	case strings.HasPrefix(action, "sleep:"):
		ms, _ := strconv.Atoi(strings.TrimPrefix(action, "sleep:"))
		time.Sleep(time.Duration(ms) * time.Millisecond)
		return
	default:
		wg.Wait()
	}
}
