//go:build linux

package integration

// Helpers for the PHP deployment tests: a service master that forks and
// replaces workers, and workers that do what PHP code can do without exploiting
// anything: run a shell command, start a program directly, start a named
// interpreter, hold a long-running helper, open a network connection.
//
// Nothing here executes a command taken from outside the test. The processes
// are the test binary under names such as <token>php-fpm8.4; the programs they
// start are /bin/sh, /bin/true and further hard links of the test binary.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func init() {
	extraHelpers["php-master"] = phpMasterMain
	extraHelpers["php-worker"] = phpWorkerMain
	extraHelpers["php-echo"] = phpEchoMain
}

// phpCmd is one line sent to a master (and from there to a worker).
type phpCmd struct {
	Worker int      `json:"worker"` // index of the worker, -1: the master itself
	Op     string   `json:"op"`
	Args   []string `json:"args,omitempty"`
	Name   string   `json:"name,omitempty"` // launch: program name in the test directory
	Mode   string   `json:"mode,omitempty"` // launch: helper mode of that program
}

// phpMasterMain is a service master like php-fpm or apache2: it forks (starts)
// workers with its own executable, replaces the ones that end and executes the
// commands it reads on stdin. args: workers, respawn delay in ms.
func phpMasterMain(args []string) {
	workers, _ := strconv.Atoi(args[0])
	delay := 20 * time.Millisecond
	if len(args) > 1 {
		if ms, err := strconv.Atoi(args[1]); err == nil {
			delay = time.Duration(ms) * time.Millisecond
		}
	}
	self := os.Args[0]
	say("master up pid=%d name=%s ppid=%d", os.Getpid(), baseName(), os.Getppid())

	if os.Getenv("PW_PHP_RELOADED") == "1" {
		// A graceful reload: the re-executed master starts the new master and ends,
		// like php-fpm does on SIGUSR2.
		cmd := exec.Command(self, args...)
		cmd.Env = withEnv(os.Environ(), "PW_PHP_RELOADED", "")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "start new master:", err)
			os.Exit(1)
		}
		say("new master started pid=%d", cmd.Process.Pid)
		time.Sleep(300 * time.Millisecond) // lets it announce itself before this one goes
		os.Exit(0)
	}

	var (
		mu       sync.Mutex
		stopping bool
		stdins   = make([]io.WriteCloser, workers)
		procs    = make([]*exec.Cmd, workers)
		wg       sync.WaitGroup
	)
	var start func(i int)
	start = func(i int) {
		cmd := exec.Command(self)
		cmd.Env = withEnv(os.Environ(), "PW_E2E_HELPER", "php-worker")
		in, err := cmd.StdinPipe()
		if err != nil {
			return
		}
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "start worker:", err)
			return
		}
		mu.Lock()
		stdins[i], procs[i] = in, cmd
		mu.Unlock()
		say("worker started idx=%d pid=%d", i, cmd.Process.Pid)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = cmd.Wait()
			mu.Lock()
			done := stopping
			mu.Unlock()
			if done {
				return
			}
			time.Sleep(delay)
			mu.Lock()
			done = stopping
			mu.Unlock()
			if !done {
				start(i)
			}
		}()
	}
	for i := 0; i < workers; i++ {
		start(i)
	}

	stop := func() {
		mu.Lock()
		stopping = true
		for _, c := range procs {
			if c != nil && c.Process != nil {
				_ = c.Process.Signal(syscall.SIGTERM)
			}
		}
		mu.Unlock()
		wg.Wait()
	}

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		var c phpCmd
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			say("bad command %q", err.Error())
			continue
		}
		switch {
		case c.Op == "stop":
			stop()
			return
		case c.Op == "reload":
			stop()
			say("reloading pid=%d", os.Getpid())
			env := withEnv(os.Environ(), "PW_PHP_RELOADED", "1")
			if err := syscall.Exec(self, append([]string{self}, os.Args[1:]...), env); err != nil {
				fmt.Fprintln(os.Stderr, "reload exec:", err)
				os.Exit(1)
			}
		case c.Worker >= 0 && c.Worker < workers:
			mu.Lock()
			in := stdins[c.Worker]
			mu.Unlock()
			if in != nil {
				_, _ = in.Write(append(append([]byte{}, sc.Bytes()...), '\n'))
			}
		default:
			say("no such worker %d", c.Worker)
		}
	}
	stop() // stdin closed: the test is gone
}

// phpWorkerMain executes what the master forwards. It ends when its stdin is
// closed (the master is gone), so no worker outlives a killed master.
func phpWorkerMain(_ []string) {
	maxReq, _ := strconv.Atoi(os.Getenv("PW_PHP_MAXREQ"))
	served := 0
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	var children []*exec.Cmd
	for sc.Scan() {
		var c phpCmd
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			say("bad command %q", err.Error())
			continue
		}
		switch c.Op {
		case "shell": // what PHP's shell_exec, system and popen do: sh -c -- <command>
			cmd := exec.Command("/bin/sh", "-c", "--", c.Args[0])
			cmd.Args[0] = "sh"
			cmd.Env = withEnv(os.Environ(), "PW_E2E_HELPER", "php-echo") // a test binary started by the shell ends at once
			cmd.Stdout, cmd.Stderr = io.Discard, os.Stderr
			err := cmd.Run()
			say("done op=shell pid=%d ok=%v", pidOf(cmd), err == nil)
		case "shell-bg": // the same, not waited for
			cmd := exec.Command("/bin/sh", "-c", "--", c.Args[0])
			cmd.Args[0] = "sh"
			cmd.Env = withEnv(os.Environ(), "PW_E2E_HELPER", "php-echo")
			cmd.Stdout, cmd.Stderr = io.Discard, os.Stderr
			if err := cmd.Start(); err != nil {
				say("failed op=shell-bg err=%q", err.Error())
				break
			}
			children = append(children, cmd)
			go func(c *exec.Cmd) { _ = c.Wait() }(cmd)
			say("started op=shell-bg pid=%d", cmd.Process.Pid)
		case "direct": // proc_open with an argument array: no shell
			cmd := exec.Command(c.Args[0], c.Args[1:]...)
			cmd.Env = withEnv(os.Environ(), "PW_E2E_HELPER", "php-echo")
			cmd.Stdout, cmd.Stderr = io.Discard, os.Stderr
			err := cmd.Run()
			say("done op=direct pid=%d ok=%v", pidOf(cmd), err == nil)
		case "launch": // a named program of the test directory with a helper mode (python3, php, ...)
			cmd := exec.Command(filepath.Join(os.Getenv("PW_E2E_DIR"), c.Name), c.Args...)
			cmd.Args[0] = c.Name
			mode := c.Mode
			if mode == "" {
				mode = "php-echo"
			}
			cmd.Env = withEnv(os.Environ(), "PW_E2E_HELPER", mode)
			cmd.Stdout, cmd.Stderr = io.Discard, os.Stderr
			if mode == "php-echo" {
				err := cmd.Run()
				say("done op=launch name=%s pid=%d ok=%v", c.Name, pidOf(cmd), err == nil)
				break
			}
			if err := cmd.Start(); err != nil {
				say("failed op=launch name=%s err=%q", c.Name, err.Error())
				break
			}
			children = append(children, cmd)
			go func(c *exec.Cmd) { _ = c.Wait() }(cmd)
			say("started op=launch name=%s pid=%d", c.Name, cmd.Process.Pid)
		case "sock": // an outbound connection made by the worker itself: no child process
			conn, err := net.DialTimeout("tcp", c.Args[0], 2*time.Second)
			if err != nil {
				say("failed op=sock err=%q", err.Error())
				break
			}
			_, _ = conn.Write([]byte(c.Args[1]))
			_ = conn.Close()
			say("done op=sock pid=%d", os.Getpid())
		case "exec": // the worker replaces its own executable: same pid, no fork
			say("exec op=exec pid=%d to=%s", os.Getpid(), c.Args[0])
			mode := c.Mode
			if mode == "" {
				mode = "php-echo"
			}
			env := withEnv(os.Environ(), "PW_E2E_HELPER", mode)
			if err := syscall.Exec(c.Args[0], c.Args, env); err != nil {
				say("failed op=exec err=%q", err.Error())
			}
		case "ping":
			say("pong pid=%d", os.Getpid())
		case "exit":
			os.Exit(0)
		default:
			say("unknown op %q", c.Op)
		}
		served++
		if maxReq > 0 && served >= maxReq {
			for _, cmd := range children {
				_ = cmd.Process.Kill()
			}
			os.Exit(0) // pm.max_requests: the master replaces this worker
		}
	}
	for _, cmd := range children {
		_ = cmd.Process.Kill()
	}
}

// pidOf is the pid of a command that has run, -1 if it never started.
func pidOf(c *exec.Cmd) int {
	if c.ProcessState == nil {
		return -1
	}
	return c.ProcessState.Pid()
}

// phpEchoMain stands in for python3, php, bash and the like: it ends at once.
// Only its name and its arguments matter.
func phpEchoMain(args []string) {
	say("echo pid=%d name=%s argc=%d", os.Getpid(), baseName(), len(args))
}

// ----------------------------------------------------------------------------
// The test side

// phpFleet is a started master with its workers.
type phpFleet struct {
	t       *testing.T
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	PID     int
	Name    string
	mu      sync.Mutex
	lines   []string
	started chan struct{}
}

// startFleet starts <dir>/<name> as a master with n workers. maxReq > 0 makes
// every worker end after that many requests (pm.max_requests).
func (d *progDir) startFleet(name string, n, maxReq int, extraEnv ...string) *phpFleet {
	d.t.Helper()
	path := d.add(name)
	cmd := exec.Command(path, strconv.Itoa(n), "20")
	env := append(os.Environ(), "PW_E2E_HELPER=php-master", "PW_E2E_DIR="+d.dir, "PW_PHP_MAXREQ="+strconv.Itoa(maxReq))
	cmd.Env = append(env, extraEnv...)
	in, err := cmd.StdinPipe()
	if err != nil {
		d.t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		d.t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		d.t.Fatalf("start %s: %v", name, err)
	}
	f := &phpFleet{t: d.t, cmd: cmd, stdin: in, PID: cmd.Process.Pid, Name: name}
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
		for sc.Scan() {
			f.mu.Lock()
			f.lines = append(f.lines, sc.Text())
			f.mu.Unlock()
		}
		_ = cmd.Wait()
	}()
	d.t.Cleanup(func() {
		_ = in.Close()
		time.Sleep(100 * time.Millisecond)
		_ = cmd.Process.Kill()
	})
	f.waitLines("worker started", n, killScale(20*time.Second))
	return f
}

// send writes one command to the master.
func (f *phpFleet) send(c phpCmd) {
	f.t.Helper()
	b, _ := json.Marshal(c)
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.stdin.Write(append(b, '\n')); err != nil {
		f.t.Fatalf("send to the master: %v", err)
	}
}

// Request sends one operation to a worker.
func (f *phpFleet) Request(worker int, op string, args ...string) {
	f.t.Helper()
	f.send(phpCmd{Worker: worker, Op: op, Args: args})
}

// Launch starts a named program from a worker.
func (f *phpFleet) Launch(worker int, name, mode string, args ...string) {
	f.t.Helper()
	f.send(phpCmd{Worker: worker, Op: "launch", Name: name, Mode: mode, Args: args})
}

// Lines returns everything the fleet printed with the prefix.
func (f *phpFleet) Lines(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, l := range f.lines {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out
}

// waitLines waits until at least n lines with the prefix exist.
func (f *phpFleet) waitLines(prefix string, n int, timeout time.Duration) []string {
	f.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if got := f.Lines(prefix); len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("fleet %s: %d line(s) with prefix %q after %s, have:\n%s", f.Name, len(f.Lines(prefix)), prefix, timeout, strings.Join(f.Lines(""), "\n"))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// WorkerPIDs returns the pids of the workers started so far, in order.
func (f *phpFleet) WorkerPIDs() []int {
	var pids []int
	for _, l := range f.Lines("worker started") {
		pids = append(pids, intAfter(l, "pid"))
	}
	return pids
}

// Stop asks the master to end its workers and itself.
func (f *phpFleet) Stop() {
	f.t.Helper()
	f.mu.Lock()
	_, _ = f.stdin.Write([]byte(`{"op":"stop"}` + "\n"))
	f.mu.Unlock()
}

// phpTokenNames returns names that look like the real executables, behind a
// unique prefix so that no other process of the test host is selected.
type phpTokenNames struct {
	Tok      outToken
	FPM      string // php-fpm8.4: versioned, like Debian
	FPMPlain string // php-fpm: unversioned, like the official images
	CLI      string // php8.4
	CGI      string // php-cgi8.4
	Apache   string // apache2
	Nginx    string // nginx
	Python   string // python3
	PHP      string // php (argv[0] of a PHP CLI start, image name php8.4 in reality)
	Helper   string // a long-running helper with a distinctive name
	Evil     string // a program that a response rule is written for
}

func phpNames() phpTokenNames {
	tok := outNewToken()
	p := tok.Prefix() + "-"
	return phpTokenNames{
		Tok: tok, FPM: p + "php-fpm8.4", FPMPlain: p + "php-fpm", CLI: p + "php8.4", CGI: p + "php-cgi8.4",
		Apache: p + "apache2", Nginx: p + "nginx", Python: p + "python3", PHP: p + "php", Helper: p + "helper", Evil: p + "evil",
	}
}
