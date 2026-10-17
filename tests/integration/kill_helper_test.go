//go:build linux

package integration

import (
	"bufio"
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
	"unsafe"

	"golang.org/x/sys/unix"
)

// The kill scenarios (kill_test.go) need controlled processes that do more
// than the recipe nodes of helper_test.go: a complete custom argument vector
// (a cut argument, a marker in argv[0]), another user id, an exec chain with
// pauses, a fork without exec, timestamps for the latency measurement, a
// creator that leaves and a control channel that starts a child at a moment
// the test chooses. All of that is one helper mode, "k", of the test binary.
//
// Every process of a scenario is the test binary under a controlled name (a
// hard link or copy in PW_E2E_DIR), so its image name is known. The tree is
// described by a kspec that is handed down in PW_E2E_KSPEC; the lines the
// processes print (all share the stdout pipe of the root) are
//
//	up pid=N name=X ppid=P t=<unix ns>
//	spawned name=X pid=N by=P t=<unix ns>          right after the child was started
//	child-ended name=X pid=N signal=S|exit=C t=<unix ns>   after the creator reaped it
//	serial-done rounds=R t=<unix ns>
//
// "child-ended ... signal=9" is the proof that the agent's SIGKILL really
// ended the process. No helper outlives its time to live (exit status 3) and,
// unless NoPdeath is set, no child outlives its creator, so an aborted test
// leaves nothing behind.

func init() { extraHelpers["k"] = kMain }

// kspec describes one controlled process.
type kspec struct {
	// Name is the program name: the link of the test binary in PW_E2E_DIR
	// that is executed, so it is the process' image.
	Name string `json:"name"`
	// Argv replaces the complete argument vector (argv[0] included). Without
	// it the arguments are the path of the program followed by Args.
	Argv []string `json:"argv,omitempty"`
	Args []string `json:"args,omitempty"`
	// Cred starts the process with this user and group id.
	Cred *kcred `json:"cred,omitempty"`
	// NoPdeath lets the process outlive its creator.
	NoPdeath bool `json:"no_pdeath,omitempty"`

	// Exit ends the process at once (a short lived program such as useradd).
	Exit bool `json:"exit,omitempty"`
	// Chain executes these programs one after the other in this very process
	// (same pid), ChainDelayMS apart. The last program lives on as LifeMS says.
	Chain        []string `json:"chain,omitempty"`
	ChainDelayMS int      `json:"chain_delay_ms,omitempty"`
	// ChainWaitFile holds the first exec of the chain back until this file exists.
	ChainWaitFile string `json:"chain_wait_file,omitempty"`
	// ForkHold forks without exec; the child, which inherits the image, sleeps
	// in raw system calls until it is killed.
	ForkHold bool `json:"fork_hold,omitempty"`
	// AwaitOrphan waits until the creator has ended before anything else.
	AwaitOrphan bool `json:"await_orphan,omitempty"`

	// Kids are started in order, DelayMS apart, and not waited for. Serial are
	// started one after the other (each is waited for first), Rounds times.
	Kids    []kspec `json:"kids,omitempty"`
	Serial  []kspec `json:"serial,omitempty"`
	Rounds  int     `json:"rounds,omitempty"`
	DelayMS int     `json:"delay_ms,omitempty"`
	// Control reads further specs (one JSON object per line) from stdin and
	// starts them, until stdin is closed.
	Control bool `json:"control,omitempty"`

	// The end of the life: Leave exits right after the kids were started,
	// LifeMS lives that long and exits with 0; otherwise the process waits for
	// its kids, and without kids until it is killed.
	Leave  bool `json:"leave,omitempty"`
	LifeMS int  `json:"life_ms,omitempty"`
	// TTLMS is the hard limit of the life (default 90 s), exit status 3.
	TTLMS int `json:"ttl_ms,omitempty"`
}

type kcred struct {
	Uid uint32 `json:"uid"`
	Gid uint32 `json:"gid"`
}

func (k kspec) json() string {
	b, err := json.Marshal(k)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// kspecNames lists every program name a spec needs as a link in PW_E2E_DIR.
func kspecNames(k kspec) []string {
	names := append([]string{k.Name}, k.Chain...)
	for _, c := range k.Kids {
		names = append(names, kspecNames(c)...)
	}
	for _, c := range k.Serial {
		names = append(names, kspecNames(c)...)
	}
	return names
}

func kNow() int64 { return time.Now().UnixNano() }

func kMain(_ []string) {
	var spec kspec
	if err := json.Unmarshal([]byte(os.Getenv("PW_E2E_KSPEC")), &spec); err != nil {
		fmt.Fprintln(os.Stderr, "k: bad PW_E2E_KSPEC:", err)
		os.Exit(2)
	}
	ttl := 90 * time.Second
	if v, err := strconv.Atoi(os.Getenv("PW_E2E_TIMEOUT_SCALE")); err == nil && v > 1 {
		ttl *= time.Duration(v) // an emulated machine needs more time
	}
	if spec.TTLMS > 0 {
		ttl = time.Duration(spec.TTLMS) * time.Millisecond
	}
	time.AfterFunc(ttl, func() {
		fmt.Printf("ttl-expired name=%s pid=%d t=%d\n", spec.Name, os.Getpid(), kNow())
		os.Exit(3)
	})
	fmt.Printf("up pid=%d name=%s ppid=%d t=%d\n", os.Getpid(), spec.Name, os.Getppid(), kNow())

	switch {
	case spec.Exit:
		return
	case len(spec.Chain) > 0:
		kChain(spec)
		return
	case spec.ForkHold:
		kForkHold(spec)
		return
	}
	if spec.AwaitOrphan {
		kAwaitOrphan()
	}
	kRunKids(spec)
}

// kEnv returns env with the given KEY=value pairs set. Entries of the same key
// are replaced: a program that is exec'd with a raw environment sees the first
// of two equal keys.
func kEnv(env []string, set ...string) []string {
	skip := make(map[string]bool, len(set))
	for _, kv := range set {
		skip[kv[:strings.IndexByte(kv, '=')]] = true
	}
	out := make([]string, 0, len(env)+len(set))
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 && skip[kv[:i]] {
			continue
		}
		out = append(out, kv)
	}
	return append(out, set...)
}

// kChain executes the next program of the chain in this process.
func kChain(spec kspec) {
	for spec.ChainWaitFile != "" {
		if _, err := os.Stat(spec.ChainWaitFile); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if spec.ChainDelayMS > 0 {
		time.Sleep(time.Duration(spec.ChainDelayMS) * time.Millisecond)
	}
	next := spec
	next.Name, next.Chain = spec.Chain[0], spec.Chain[1:]
	next.Argv, next.Args, next.ChainWaitFile = nil, nil, ""
	path := filepath.Join(os.Getenv("PW_E2E_DIR"), next.Name)
	err := syscall.Exec(path, []string{path}, kEnv(os.Environ(), "PW_E2E_HELPER=k", "PW_E2E_KSPEC="+next.json()))
	fmt.Printf("exec-failed name=%s err=%q\n", next.Name, err.Error())
	os.Exit(1)
}

// kForkHold forks without exec and waits for the child. In the forked child
// of a threaded Go program only raw system calls are safe, so the child does
// nothing but sleep and exit.
func kForkHold(spec kspec) {
	pid, _, errno := unix.RawSyscall(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0)
	if errno != 0 {
		fmt.Fprintln(os.Stderr, "clone:", errno)
		os.Exit(1)
	}
	if pid == 0 {
		ts := unix.Timespec{Sec: 60}
		unix.RawSyscall6(unix.SYS_NANOSLEEP, uintptr(unsafe.Pointer(&ts)), 0, 0, 0, 0, 0)
		unix.RawSyscall(unix.SYS_EXIT_GROUP, 0, 0, 0)
		return
	}
	name := spec.Name + "-fork"
	fmt.Printf("spawned name=%s pid=%d by=%d t=%d\n", name, pid, os.Getpid(), kNow())
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(int(pid), &ws, 0, nil); err != nil {
		fmt.Fprintln(os.Stderr, "wait4:", err)
		os.Exit(1)
	}
	kReportEnd(name, int(pid), ws, kNow())
}

// kAwaitOrphan returns once the creator has ended (the parent is another
// process now) and the end had a moment to be processed.
func kAwaitOrphan() {
	creator, _ := strconv.Atoi(os.Getenv("PW_E2E_CREATOR"))
	for creator > 0 && os.Getppid() == creator {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
}

func kReportEnd(name string, pid int, ws syscall.WaitStatus, t1 int64) {
	if ws.Signaled() {
		fmt.Printf("child-ended name=%s pid=%d signal=%d t=%d\n", name, pid, int(ws.Signal()), t1)
		return
	}
	fmt.Printf("child-ended name=%s pid=%d exit=%d t=%d\n", name, pid, ws.ExitStatus(), t1)
}

type kKid struct {
	done chan struct{}
}

// kStart starts a child and reports when it ended; it returns nil when the
// child could not be started.
func kStart(k kspec, wg *sync.WaitGroup) *kKid {
	path := filepath.Join(os.Getenv("PW_E2E_DIR"), k.Name)
	argv := k.Argv
	if len(argv) == 0 {
		argv = append([]string{path}, k.Args...)
	}
	cmd := &exec.Cmd{Path: path, Args: argv, Stdout: os.Stdout, Stderr: os.Stderr}
	cmd.Env = append(os.Environ(), "PW_E2E_HELPER=k", "PW_E2E_KSPEC="+k.json(), "PW_E2E_CREATOR="+strconv.Itoa(os.Getpid()))
	attr := &syscall.SysProcAttr{}
	if !k.NoPdeath {
		attr.Pdeathsig = syscall.SIGKILL
	}
	if k.Cred != nil {
		attr.Credential = &syscall.Credential{Uid: k.Cred.Uid, Gid: k.Cred.Gid}
		cmd.Dir = "/"
	}
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		fmt.Printf("spawn-failed name=%s err=%q\n", k.Name, err.Error())
		return nil
	}
	t0 := kNow()
	pid := cmd.Process.Pid
	fmt.Printf("spawned name=%s pid=%d by=%d t=%d\n", k.Name, pid, os.Getpid(), t0)
	kid := &kKid{done: make(chan struct{})}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(kid.done)
		_ = cmd.Wait()
		t1 := kNow()
		ws, _ := cmd.ProcessState.Sys().(syscall.WaitStatus)
		kReportEnd(k.Name, pid, ws, t1)
	}()
	return kid
}

func kRunKids(spec kspec) {
	var wg sync.WaitGroup
	pause := func() {
		if spec.DelayMS > 0 {
			time.Sleep(time.Duration(spec.DelayMS) * time.Millisecond)
		}
	}
	for _, k := range spec.Kids {
		pause()
		kStart(k, &wg)
	}
	if len(spec.Serial) > 0 {
		rounds := max(spec.Rounds, 1)
		for r := 0; r < rounds; r++ {
			for _, k := range spec.Serial {
				pause()
				if kid := kStart(k, &wg); kid != nil {
					<-kid.done
				}
			}
		}
		fmt.Printf("serial-done rounds=%d t=%d\n", rounds, kNow())
	}
	switch {
	case spec.Control:
		kControl(&wg)
	case spec.Leave:
	case spec.LifeMS > 0:
		time.Sleep(time.Duration(spec.LifeMS) * time.Millisecond)
	case len(spec.Kids)+len(spec.Serial) > 0:
		wg.Wait()
	default:
		time.Sleep(time.Hour) // until killed; the time to live ends it at the latest
	}
}

// kControl starts every spec that arrives as a JSON line on stdin.
func kControl(wg *sync.WaitGroup) {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		var k kspec
		if err := json.Unmarshal(sc.Bytes(), &k); err != nil {
			fmt.Printf("bad-command err=%q\n", err.Error())
			continue
		}
		kStart(k, wg)
	}
}
