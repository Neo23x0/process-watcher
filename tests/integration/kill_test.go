//go:build linux

package integration

// End to end tests of the rule based termination of observed descendants
// (the kill feature requirements). Every test starts the real agent
// with a kill configuration, runs real processes with controlled names (see
// kill_helper_test.go) and verifies two independent things: what the agent
// writes to the JSONL log, and that the process really ended - or really did
// not - through the report of its creator ("child-ended ... signal=9"), the
// exit record of the kernel and /proc.
//
// Safety and isolation: other test suites may run on the same machine and in
// the same PID namespace, and a watch pattern is a substring match. Every
// test therefore creates a random token (killEnv) that is part of every
// program name, of the watch pattern and of every kill rule. The kill rules
// match only that token, the agent only reacts to descendants of the watched
// roots, and the tests send no signal themselves except for the cleanup of
// their own processes (everything whose executable lies in the private
// directory of the test).

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ----------------------------------------------------------------------------
// Names

// killEnv gives a test names of its own: <token>-<role> for every program, and
// <token>-root as the one name the watch pattern matches (no other program of
// the test contains "-root", so it is the only watched root unless a test
// creates more of them with a name that starts with <token>-root).
type killEnv struct{ tok string }

func newKillEnv(t *testing.T) killEnv {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return killEnv{tok: "pwk" + hex.EncodeToString(b[:])}
}

// n is the program name of a role.
func (ke killEnv) n(role string) string { return ke.tok + "-" + role }

// root is the name of the watched root and the watch pattern.
func (ke killEnv) root() string { return ke.n("root") }

// cfg is a configuration that watches the root of this test and kills with
// the given rules; mods adjust it.
func (ke killEnv) cfg(strs, regex []string, mods ...func(*agentCfg)) agentCfg {
	c := agentCfg{Watch: []string{ke.root()}, KillEnabled: true, KillStrings: strs, KillRegex: regex}
	for _, m := range mods {
		m(&c)
	}
	return c
}

// want is the usual expectation for a killed direct child of the root: the
// first exec triggered the action and the signal was accepted.
func (ke killEnv) want(pid int, image string, rootPID int) killWant {
	return killWant{
		PID: pid, Image: image, RootImage: ke.root(), RootPID: rootPID, ParentPID: rootPID, Depth: 1, Ancestors: []int{rootPID},
		ExecIndex: 1, Trigger: "process.exec", InLog: true, Outcome: "signal_sent", Attempted: true,
	}
}

// ----------------------------------------------------------------------------
// Controlled processes

// newKillDir is a progDir whose processes are all killed when the test ends:
// a created child lives on only as long as its creator, but orphans (and a
// helper that lost its creator) would outlive the test.
func newKillDir(t *testing.T) *progDir {
	t.Helper()
	d := newProgDir(t)
	t.Cleanup(func() { killProcsIn(d.dir) })
	return d
}

// newSharedKillDir is newKillDir for processes that run as another user: the
// directory and the path to it must be accessible for that user.
func newSharedKillDir(t *testing.T) *progDir {
	t.Helper()
	dir, err := os.MkdirTemp("", "pwkill")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Cleanup(func() { killProcsIn(dir) })
	return &progDir{t: t, dir: dir}
}

// killProcsIn kills every process that executes a file inside dir, the
// private directory of one test. The signal goes through a pidfd that was
// opened before the executable was looked at.
func killProcsIn(dir string) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	prefix := dir + string(os.PathSeparator)
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			continue
		}
		if exe, err := os.Readlink("/proc/" + e.Name() + "/exe"); err == nil && strings.HasPrefix(exe, prefix) {
			_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		}
		_ = unix.Close(fd)
	}
}

// startK starts the root of a spec tree. The arguments of the root process are
// spec.Args.
func (d *progDir) startK(root kspec) (*prog, *killTap) {
	d.t.Helper()
	for _, n := range kspecNames(root) {
		d.add(n)
	}
	p := d.startEnv(root.Name, "k", []string{"PW_E2E_KSPEC=" + root.json()}, root.Args...)
	return p, newKillTap(p)
}

// killCtl starts further children of a control root at the moment the test
// chooses.
type killCtl struct {
	d  *progDir
	in io.WriteCloser
}

// startKControl starts a root that only reads commands from stdin.
func (d *progDir) startKControl(root kspec) (*prog, *killTap, *killCtl) {
	d.t.Helper()
	root.Control = true
	for _, n := range kspecNames(root) {
		d.add(n)
	}
	cmd := exec.Command(d.add(root.Name))
	cmd.Env = append(os.Environ(), "PW_E2E_HELPER=k", "PW_E2E_DIR="+d.dir, "PW_E2E_KSPEC="+root.json())
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
		d.t.Fatalf("start %s: %v", root.Name, err)
	}
	p := &prog{t: d.t, cmd: cmd, PID: cmd.Process.Pid, lines: make(chan string, 100000), done: make(chan struct{})}
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
		for sc.Scan() {
			p.lines <- sc.Text()
		}
		_ = cmd.Wait()
		p.state = cmd.ProcessState
		close(p.done)
		close(p.lines)
	}()
	d.t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Process.Kill()
	})
	return p, newKillTap(p), &killCtl{d: d, in: in}
}

// spawn asks the control root to start a child.
func (c *killCtl) spawn(spec kspec) {
	c.d.t.Helper()
	for _, n := range kspecNames(spec) {
		c.d.add(n)
	}
	if _, err := c.in.Write(append([]byte(spec.json()), '\n')); err != nil {
		c.d.t.Fatalf("command to the control root: %v", err)
	}
}

// killLine is one line printed by the processes of a scenario.
type killLine struct {
	Text string
	At   time.Time // when the test read it
}

// killTap collects the lines of a root process (they include the lines of all
// its descendants, which share its stdout) without losing the early ones.
type killTap struct {
	mu     sync.Mutex
	lines  []killLine
	closed bool
	wake   chan struct{}
}

func newKillTap(p *prog) *killTap {
	k := &killTap{wake: make(chan struct{})}
	go func() {
		for l := range p.lines {
			k.push(killLine{Text: l, At: time.Now()}, false)
		}
		k.push(killLine{}, true)
	}()
	return k
}

func (k *killTap) push(l killLine, closed bool) {
	k.mu.Lock()
	if closed {
		k.closed = true
	} else {
		k.lines = append(k.lines, l)
	}
	old := k.wake
	k.wake = make(chan struct{})
	k.mu.Unlock()
	close(old)
}

func (k *killTap) dump() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var b strings.Builder
	start := 0
	if len(k.lines) > 60 {
		start = len(k.lines) - 60
	}
	for _, l := range k.lines[start:] {
		b.WriteString("  " + l.Text + "\n")
	}
	return b.String()
}

// await waits for the first line that match accepts.
func (k *killTap) await(t *testing.T, timeout time.Duration, what string, match func(string) bool) killLine {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		k.mu.Lock()
		for _, l := range k.lines {
			if match(l.Text) {
				k.mu.Unlock()
				return l
			}
		}
		closed, wake := k.closed, k.wake
		k.mu.Unlock()
		if closed {
			t.Fatalf("the output ended before %s; the lines so far:\n%s", what, k.dump())
		}
		select {
		case <-wake:
		case <-deadline.C:
			t.Fatalf("timeout (%s) waiting for %s; the lines so far:\n%s", timeout, what, k.dump())
		}
	}
}

// with returns all lines that start with prefix.
func (k *killTap) with(prefix string) []killLine {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []killLine
	for _, l := range k.lines {
		if strings.HasPrefix(l.Text, prefix) {
			out = append(out, l)
		}
	}
	return out
}

func kInt64(line, key string) int64 {
	n, _ := strconv.ParseInt(strAfter(line, key), 10, 64)
	return n
}

// killKid is a started child as its creator reported it.
type killKid struct {
	Name string
	PID  int
	T0   int64 // time on the creator's clock right after the start returned
}

func parseKid(l killLine) killKid {
	return killKid{Name: strAfter(l.Text, "name"), PID: intAfter(l.Text, "pid"), T0: kInt64(l.Text, "t")}
}

// spawned waits for the report that the child with this name was started.
func (k *killTap) spawned(t *testing.T, name string) killKid {
	t.Helper()
	l := k.await(t, killScale(30*time.Second), "the start of "+name, func(s string) bool {
		return strings.HasPrefix(s, "spawned name="+name+" ")
	})
	return parseKid(l)
}

// started lists the children with this name that were started so far.
func (k *killTap) started(name string) []killKid {
	var kids []killKid
	for _, l := range k.with("spawned name=" + name + " ") {
		kids = append(kids, parseKid(l))
	}
	return kids
}

// up waits for the first line of the process with this name and returns its pid.
func (k *killTap) up(t *testing.T, name string) int {
	t.Helper()
	l := k.await(t, killScale(30*time.Second), name+" to be up", func(s string) bool {
		return strings.HasPrefix(s, "up ") && strAfter(s, "name") == name
	})
	return intAfter(l.Text, "pid")
}

// killEnd is the report of a creator about the end of a child.
type killEnd struct {
	PID    int
	Signal int // 0 when the child exited by itself
	Exit   int // exit status, -1 when it was ended by a signal
	T1     int64
	At     time.Time
	Line   string
}

// ended waits for the report about the end of the child with this pid.
func (k *killTap) ended(t *testing.T, pid int, timeout time.Duration) killEnd {
	t.Helper()
	l := k.await(t, timeout, fmt.Sprintf("the end of process %d", pid), func(s string) bool {
		return strings.HasPrefix(s, "child-ended ") && intAfter(s, "pid") == pid
	})
	e := killEnd{PID: pid, Exit: -1, T1: kInt64(l.Text, "t"), At: l.At, Line: l.Text}
	if strings.Contains(l.Text, " signal=") {
		e.Signal = intAfter(l.Text, "signal")
	} else {
		e.Exit = intAfter(l.Text, "exit")
	}
	return e
}

// requireKilled checks that the creator saw the child end by SIGKILL.
func requireKilled(t *testing.T, e killEnd) {
	t.Helper()
	if e.Signal != int(syscall.SIGKILL) {
		t.Fatalf("process %d must end by SIGKILL, its creator reported: %s", e.PID, e.Line)
	}
}

// requireEndedByItself checks that the child was not killed.
func requireEndedByItself(t *testing.T, e killEnd) {
	t.Helper()
	if e.Signal != 0 || e.Exit != 0 {
		t.Fatalf("process %d must end by itself with exit status 0, its creator reported: %s", e.PID, e.Line)
	}
}

// killProcStart returns the start time (clock ticks) of a process and whether it
// is running (not gone, not a zombie).
func killProcStart(pid int) (start uint64, running bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(string(b[i+1:])) // f[0] is the state, f[19] the start time
	if len(f) < 20 {
		return 0, false
	}
	start, _ = strconv.ParseUint(f[19], 10, 64)
	return start, f[0] != "Z" && f[0] != "X"
}

// requireRunning checks that the process is still the same running one.
func requireRunning(t *testing.T, what string, pid int, start uint64) {
	t.Helper()
	if s, ok := killProcStart(pid); !ok || s != start {
		t.Errorf("%s (pid %d) must still be running", what, pid)
	}
}

func killWaitGone(t *testing.T, what string, pid int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if _, ok := killProcStart(pid); !ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s (pid %d) is still running %s after it should have been killed", what, pid, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ----------------------------------------------------------------------------
// The agent

// startAgentCustom is startAgent for a configuration that agentCfg cannot
// express and for extra command line arguments; wrap is a command that starts
// the agent (for example setpriv).
func startAgentCustom(t *testing.T, render func(logPath string) string, wrap []string, extra ...string) *agent {
	t.Helper()
	requireRoot(t)
	dir := t.TempDir()
	a := &agent{t: t, dir: dir, LogPath: filepath.Join(dir, "events.jsonl"), CfgPath: filepath.Join(dir, "config.yaml"), stderr: &syncBuf{}}
	if err := os.WriteFile(a.CfgPath, []byte(render(a.LogPath)), 0o600); err != nil {
		t.Fatal(err)
	}
	argv := append(append(append([]string{}, wrap...), agentBin, "--config", a.CfgPath), extra...)
	a.cmd = exec.Command(argv[0], argv[1:]...)
	a.cmd.Stderr = a.stderr
	if err := a.cmd.Start(); err != nil {
		t.Fatalf("start %v: %v", argv[0], err)
	}
	a.done = make(chan struct{})
	go func() {
		_ = a.cmd.Wait()
		a.exit = a.cmd.ProcessState.ExitCode()
		close(a.done)
	}()
	t.Cleanup(func() { a.Stop() })
	began := time.Now()
	a.waitReady(killScale(60 * time.Second))
	if took := time.Since(began); took > 3*time.Second {
		t.Logf("the agent needed %s to become ready", took.Round(10*time.Millisecond))
	}
	return a
}

// killScale scales a timeout by PW_E2E_TIMEOUT_SCALE (default 1): in an
// emulated machine (QEMU without KVM) everything takes many times as long.
// Only the time the tests wait for something is scaled; the behaviour that is
// checked does not depend on it.
func killScale(d time.Duration) time.Duration {
	if v, err := strconv.Atoi(os.Getenv("PW_E2E_TIMEOUT_SCALE")); err == nil && v > 1 {
		return d * time.Duration(v)
	}
	return d
}

// killAgent starts the agent with a configuration of agentCfg. It is startAgent
// of the harness with a ready timeout that can be scaled.
func killAgent(t *testing.T, cfg agentCfg) *agent {
	t.Helper()
	return startAgentCustom(t, cfg.render, nil)
}

// killStop ends the agent with SIGTERM, requires exit status 0 and returns the
// agent.stopped event with the final counters.
func killStop(t *testing.T, a *agent) Ev {
	t.Helper()
	if code := a.Stop(); code != 0 {
		t.Fatalf("agent exit code %d after SIGTERM, want 0:\n%s", code, a.stderr.String())
	}
	st := ofType(a.Events(), "agent.stopped")
	if len(st) != 1 {
		t.Fatalf("%d agent.stopped events, want 1", len(st))
	}
	return st[0]
}

// requireCounter checks a number of details.response of agent.health or
// agent.stopped.
func requireCounter(t *testing.T, ev Ev, name string, want int) {
	t.Helper()
	if got := ev.num("details.response." + name); got != want {
		t.Errorf("%s details.response.%s = %d, want %d (%v)", ev.Type(), name, got, want, ev.get("details.response"))
	}
}

// killHealthAfter returns the first agent.health report that was written after
// the event with this sequence number. The counters are updated before an audit
// result is written, so the report includes every action that is finished.
func killHealthAfter(t *testing.T, a *agent, seq int) Ev {
	t.Helper()
	var found Ev
	a.waitEvents(killScale(15*time.Second), "an agent.health report after event #"+strconv.Itoa(seq), func(evs []Ev) bool {
		for _, h := range ofType(evs, "agent.health") {
			if h.Seq() > seq {
				found = h
				return true
			}
		}
		return false
	})
	return found
}

// killAttempts counts the results that tell of a signal attempt.
func killAttempts(evs []Ev) int {
	n := 0
	for _, e := range ofType(evs, "response.kill_result") {
		if e.get("details.signal_attempted_at") != nil {
			n++
		}
	}
	return n
}

// ----------------------------------------------------------------------------
// Events

func killEvs(evs []Ev, typ string, pid int) []Ev {
	if pid <= 0 {
		return nil
	}
	return filterEv(evs, func(e Ev) bool { return e.Type() == typ && e.PID() == pid })
}

func killHas(typ string, pid int) func([]Ev) bool {
	return func(evs []Ev) bool { return len(killEvs(evs, typ, pid)) > 0 }
}

func killAll(fs ...func([]Ev) bool) func([]Ev) bool {
	return func(evs []Ev) bool {
		for _, f := range fs {
			if !f(evs) {
				return false
			}
		}
		return true
	}
}

// killResponses are all response.* events.
func killResponses(evs []Ev) []Ev {
	return filterEv(evs, func(e Ev) bool { return strings.HasPrefix(e.Type(), "response.") })
}

func killDump(evs []Ev, pid int) string {
	var b strings.Builder
	for _, e := range evs {
		if e.PID() == pid {
			fmt.Fprintf(&b, "  #%d %s outcome=%v action=%v\n", e.Seq(), e.Type(), e.get("details.outcome"), e.get("details.action_id"))
		}
	}
	return b.String()
}

var killUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// killNS reads a nanosecond value, which the contract writes as a decimal string.
func killNS(e Ev, path string) (int64, bool) {
	s, ok := e.get(path).(string)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

func killRuleKey(ref, typ, pattern, field string, arg int) string {
	k := ref + "|" + typ + "|" + pattern + "|" + field
	if arg >= 0 {
		k += "|" + strconv.Itoa(arg)
	}
	return k
}

// killRuleKeys lists details.rules of an audit event, sorted.
func killRuleKeys(e Ev) []string {
	arr, _ := e.get("details.rules").([]any)
	var keys []string
	for _, it := range arr {
		m, _ := it.(map[string]any)
		arg := -1
		if v, ok := m["arg_index"].(float64); ok {
			arg = int(v)
		}
		keys = append(keys, killRuleKey(fmt.Sprint(m["ref"]), fmt.Sprint(m["type"]), fmt.Sprint(m["pattern"]), fmt.Sprint(m["field"]), arg))
	}
	sort.Strings(keys)
	return keys
}

func killAncestorPIDs(e Ev) []int {
	arr, _ := e.get("lineage.ancestors").([]any)
	var out []int
	for _, a := range arr {
		parts := strings.Split(fmt.Sprint(a), ":") // boot_id:pid:start_boot_ns
		pid := -1
		if len(parts) >= 3 {
			pid, _ = strconv.Atoi(parts[len(parts)-2])
		}
		out = append(out, pid)
	}
	return out
}

// killWant is what one pair of audit events must say.
type killWant struct {
	PID       int
	Image     string
	RootImage string
	RootPID   int
	ParentPID int // 0: not checked
	Depth     int
	Ancestors []int // pids from the root to the parent; nil: not checked
	ExecIndex int
	Trigger   string   // details.trigger_event_type
	InLog     bool     // the trigger event itself is in the log (false: it was suppressed)
	Rules     []string // killRuleKey of every expected hit
	Outcome   string
	DryRun    bool
	Attempted bool   // a signal attempt time is expected in the result
	Errno     string // details.error.errno; empty: no error
	Reason    string // details.reason; empty: none
}

// killPairs returns the audit events of a process.
func killPairs(evs []Ev, pid int) (reqs, ress []Ev) {
	return killEvs(evs, "response.kill_requested", pid), killEvs(evs, "response.kill_result", pid)
}

// requireKillPair checks the one audit pair of a process.
func requireKillPair(t *testing.T, evs []Ev, w killWant) (req, res Ev) {
	t.Helper()
	reqs, ress := killPairs(evs, w.PID)
	if len(reqs) != 1 || len(ress) != 1 {
		t.Fatalf("pid %d: %d response.kill_requested and %d response.kill_result events, want exactly one each:\n%s",
			w.PID, len(reqs), len(ress), killDump(evs, w.PID))
	}
	checkKillPair(t, evs, reqs[0], ress[0], w)
	return reqs[0], ress[0]
}

// checkKillPair checks the contract of one audit pair against what is expected.
func checkKillPair(t *testing.T, evs []Ev, req, res Ev, w killWant) {
	t.Helper()
	id := req.str("details.action_id")
	if !killUUID.MatchString(id) {
		t.Errorf("details.action_id %q is no UUID", id)
	}
	if res.str("details.action_id") != id {
		t.Errorf("the pair does not share the action id: %q and %q", id, res.str("details.action_id"))
	}
	if req.Seq() >= res.Seq() {
		t.Errorf("the decision (#%d) must be written before the result (#%d)", req.Seq(), res.Seq())
	}
	if got := req.str("details.outcome"); got != "pending" {
		t.Errorf("response.kill_requested outcome %q, want pending", got)
	}
	if got := res.str("details.outcome"); got != w.Outcome {
		t.Errorf("response.kill_result outcome %q, want %q (error %v, reason %v)", got, w.Outcome, res.get("details.error"), res.get("details.reason"))
	}
	if got := req.str("details.trigger_event_id"); !killUUID.MatchString(got) || res.str("details.trigger_event_id") != got {
		t.Errorf("trigger_event_id %q / %q", got, res.str("details.trigger_event_id"))
	}
	for _, e := range []Ev{req, res} {
		if e.str("source") != "agent" {
			t.Errorf("%s: source %q, want agent", e.Type(), e.str("source"))
		}
		if e.num("schema_version") != 1 || !killUUID.MatchString(e.str("event_id")) {
			t.Errorf("%s: envelope %v %v", e.Type(), e.get("schema_version"), e.get("event_id"))
		}
		if e.str("details.action") != "kill" || e.str("details.signal") != "SIGKILL" {
			t.Errorf("%s: action %q signal %q", e.Type(), e.str("details.action"), e.str("details.signal"))
		}
		if dry, _ := e.get("details.dry_run").(bool); dry != w.DryRun {
			t.Errorf("%s: dry_run %v, want %v", e.Type(), e.get("details.dry_run"), w.DryRun)
		}
		if e.num("details.exec_index") != w.ExecIndex {
			t.Errorf("%s: exec_index %d, want %d", e.Type(), e.num("details.exec_index"), w.ExecIndex)
		}
		if e.str("details.trigger_event_type") != w.Trigger {
			t.Errorf("%s: trigger_event_type %q, want %q", e.Type(), e.str("details.trigger_event_type"), w.Trigger)
		}
		if got := killRuleKeys(e); !equalSorted(got, w.Rules) {
			t.Errorf("%s: details.rules\n got %q\nwant %q", e.Type(), got, w.Rules)
		}
		if f, _ := e.get("filter.excluded").(bool); f {
			t.Errorf("%s: an audit event is never excluded: %v", e.Type(), e.get("filter"))
		}
		if e.str("details.decided_at") == "" || e.str("timestamp") == "" {
			t.Errorf("%s: no decision time", e.Type())
		}
		// Target, parent, root and lineage as copied at decision time.
		if e.PID() != w.PID || e.Image() != w.Image || e.str("process.image_state") == "" {
			t.Errorf("%s: process pid %d image %q state %q, want pid %d image %q", e.Type(), e.PID(), e.Image(), e.str("process.image_state"), w.PID, w.Image)
		}
		if pid := e.PID(); !strings.HasSuffix(e.ID(), ":"+strconv.Itoa(pid)+":"+e.str("process.start_boot_ns")) || e.str("process.start_boot_ns") == "" {
			t.Errorf("%s: process_id %q does not match pid %d and start_boot_ns %q", e.Type(), e.ID(), pid, e.str("process.start_boot_ns"))
		}
		for _, f := range []string{"process.uid", "process.euid", "process.gid"} {
			if e.num(f) < 0 {
				t.Errorf("%s: %s missing", e.Type(), f)
			}
		}
		if e.RootPID() != w.RootPID || e.str("root.image") != w.RootImage || e.str("root.process_id") == "" {
			t.Errorf("%s: root %v, want pid %d image %s", e.Type(), e.get("root"), w.RootPID, w.RootImage)
		}
		if w.ParentPID != 0 && (e.num("parent.pid") != w.ParentPID || e.str("parent.process_id") == "" || e.str("parent.relationship_source") == "") {
			t.Errorf("%s: parent %v, want pid %d", e.Type(), e.get("parent"), w.ParentPID)
		}
		if e.Role() != "descendant" || e.Depth() != w.Depth {
			t.Errorf("%s: lineage %v, want a descendant at depth %d", e.Type(), e.get("lineage"), w.Depth)
		}
		if complete, _ := e.get("lineage.complete").(bool); !complete {
			t.Errorf("%s: lineage not complete: %v", e.Type(), e.get("lineage"))
		}
		if w.Ancestors != nil && !reflect.DeepEqual(killAncestorPIDs(e), w.Ancestors) {
			t.Errorf("%s: ancestors %v, want %v", e.Type(), killAncestorPIDs(e), w.Ancestors)
		}
	}
	for _, f := range []string{"process", "parent", "root", "lineage", "data_quality"} {
		if !reflect.DeepEqual(req.get(f), res.get(f)) {
			t.Errorf("request and result describe %s differently:\n%v\n%v", f, req.get(f), res.get(f))
		}
	}

	// The error and the reason of the result.
	if w.Errno == "" {
		if res.get("details.error") != nil {
			t.Errorf("unexpected error %v", res.get("details.error"))
		}
	} else if got := res.str("details.error.errno"); got != w.Errno || res.num("details.error.code") <= 0 || res.str("details.error.op") == "" {
		t.Errorf("details.error %v, want errno %s", res.get("details.error"), w.Errno)
	}
	if got := res.str("details.reason"); got != w.Reason {
		t.Errorf("details.reason %q, want %q", got, w.Reason)
	}
	if req.get("details.reason") != nil || req.get("details.error") != nil {
		t.Errorf("a pending decision has neither a reason nor an error: %v %v", req.get("details.reason"), req.get("details.error"))
	}

	// Times: the decision always, the attempt only when there was one.
	trigNS, ok1 := killNS(res, "details.trigger_boot_ns")
	decNS, ok2 := killNS(res, "details.decided_boot_ns")
	decLat, ok3 := killNS(res, "details.decision_latency_ns")
	if !ok1 || !ok2 || !ok3 || trigNS <= 0 || decLat < 0 || decNS-trigNS != decLat {
		t.Errorf("decision times: trigger %v decided %v latency %v", res.get("details.trigger_boot_ns"), res.get("details.decided_boot_ns"), res.get("details.decision_latency_ns"))
	}
	if req.get("details.signal_attempted_at") != nil || req.get("details.attempt_latency_ns") != nil || req.get("details.signal_attempt_boot_ns") != nil {
		t.Errorf("the pending decision has no attempt yet")
	}
	attempted := res.get("details.signal_attempted_at") != nil
	if attempted != w.Attempted {
		t.Errorf("signal_attempted_at %v, attempt expected: %v", res.get("details.signal_attempted_at"), w.Attempted)
	}
	if w.Attempted {
		lat, ok := killNS(res, "details.attempt_latency_ns")
		attNS, ok2 := killNS(res, "details.signal_attempt_boot_ns")
		if !ok || !ok2 || lat <= 0 || lat < decLat || attNS-trigNS != lat {
			t.Errorf("attempt times: boot %v latency %v (decision latency %d)", res.get("details.signal_attempt_boot_ns"), res.get("details.attempt_latency_ns"), decLat)
		}
	} else if res.get("details.attempt_latency_ns") != nil || res.get("details.signal_attempt_boot_ns") != nil {
		t.Errorf("no attempt, but attempt times: %v", res.get("details"))
	}

	// The event that triggered the decision.
	tid := req.str("details.trigger_event_id")
	trig := filterEv(evs, func(e Ev) bool { return e.str("event_id") == tid })
	switch {
	case w.InLog && len(trig) != 1:
		t.Errorf("trigger_event_id %s: %d events with this id in the log, want the %s event", tid, len(trig), w.Trigger)
	case w.InLog:
		if trig[0].Type() != w.Trigger || trig[0].ID() != req.ID() {
			t.Errorf("trigger event is %s of %s, want %s of %s", trig[0].Type(), trig[0].ID(), w.Trigger, req.ID())
		}
		if trig[0].Seq() >= req.Seq() {
			t.Errorf("the trigger event (#%d) must precede the decision (#%d)", trig[0].Seq(), req.Seq())
		}
	case len(trig) != 0:
		t.Errorf("the trigger event was to be suppressed from the log, but is there: %s", trig[0].Line)
	}
}

func equalSorted(a, b []string) bool {
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	return reflect.DeepEqual(a, b)
}

// requireKillExit checks the later exit record of a killed process: the
// signal the kernel reported and the correlation with the action.
func requireKillExit(t *testing.T, evs []Ev, pid int, actionID string) Ev {
	t.Helper()
	exits := killEvs(evs, "process.exit", pid)
	if len(exits) != 1 {
		t.Fatalf("pid %d: %d process.exit events, want 1:\n%s", pid, len(exits), killDump(evs, pid))
	}
	x := exits[0]
	if x.num("details.signal") != 9 || x.get("details.exit_code") != nil {
		t.Errorf("exit of pid %d: signal %v exit_code %v, want signal 9", pid, x.get("details.signal"), x.get("details.exit_code"))
	}
	if x.str("details.response_action_id") != actionID {
		t.Errorf("exit of pid %d: response_action_id %q, want the action %q", pid, x.str("details.response_action_id"), actionID)
	}
	if x.str("details.exit_source") != "kernel" {
		t.Errorf("exit of pid %d: exit_source %q", pid, x.str("details.exit_source"))
	}
	return x
}

// requireNoAudit checks that nothing was decided about a process.
func requireNoAudit(t *testing.T, evs []Ev, what string, pid int) {
	t.Helper()
	for _, typ := range []string{"response.kill_requested", "response.kill_result"} {
		if got := killEvs(evs, typ, pid); len(got) != 0 {
			t.Errorf("%s (pid %d) must not be a target, but there is %s", what, pid, got[0].Line)
		}
	}
}

// requireDecisions checks the number of decisions in the whole run.
func requireDecisions(t *testing.T, evs []Ev, want int) {
	t.Helper()
	if n := len(ofType(evs, "response.kill_requested")); n != want {
		t.Errorf("%d decisions in the run, want %d", n, want)
	}
	if n := len(ofType(evs, "response.kill_result")); n > want {
		t.Errorf("%d results in the run for %d decisions", n, want)
	}
}

// ----------------------------------------------------------------------------
// A remote receiver

// killLoopbackWorks tells whether a TCP connection to a listener on 127.0.0.1
// can be made at all: the guest of the QEMU runner has no network configuration,
// and a receiver cannot be reached there.
func killLoopbackWorks() bool {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// killSink is a TCP receiver that collects the lines it gets.
type killSink struct {
	ln    net.Listener
	mu    sync.Mutex
	lines []string
}

func newKillSink(t *testing.T) *killSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &killSink{ln: ln}
	var conns []net.Conn
	var cmu sync.Mutex
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			cmu.Lock()
			conns = append(conns, c)
			cmu.Unlock()
			go func() {
				sc := bufio.NewScanner(c)
				sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
				for sc.Scan() {
					s.mu.Lock()
					s.lines = append(s.lines, sc.Text())
					s.mu.Unlock()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		cmu.Lock()
		defer cmu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return s
}

func (s *killSink) Addr() string { return s.ln.Addr().String() }

func (s *killSink) Events() []Ev {
	s.mu.Lock()
	defer s.mu.Unlock()
	return parseEvents([]byte(strings.Join(s.lines, "\n")))
}

// ----------------------------------------------------------------------------
// 1. The feature is off

func TestKillFeatureOff(t *testing.T) {
	cases := []struct {
		name   string
		render func(ke killEnv) func(string) string
		extra  []string
	}{
		{"no kill section", func(ke killEnv) func(string) string { return agentCfg{Watch: []string{ke.root()}}.render }, nil},
		{"enabled false with rules", func(ke killEnv) func(string) string {
			return func(p string) string {
				return agentCfg{Watch: []string{ke.root()}}.render(p) + "kill:\n  enabled: false\n  fields: [image]\n  strings: " +
					yamlList([]string{ke.n("victim")}) + "\n  regex: " + yamlList([]string{"^" + ke.n("victim") + "$"}) + "\n"
			}
		}, nil},
		{"flag overrides yaml", func(ke killEnv) func(string) string {
			return ke.cfg([]string{ke.n("victim")}, nil).render
		}, []string{"--kill-enabled=false"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ke := newKillEnv(t)
			victim, bystander := ke.n("victim"), ke.n("bystander")
			a := startAgentCustom(t, tc.render(ke), nil, tc.extra...)
			d := newKillDir(t)
			_, tp := d.startK(kspec{Name: ke.root(), Kids: []kspec{
				{Name: victim, LifeMS: 1500},
				{Name: bystander, LifeMS: 1500},
			}})
			vic := tp.spawned(t, victim)
			requireEndedByItself(t, tp.ended(t, vic.PID, killScale(20*time.Second)))
			evs := a.waitEvents(killScale(15*time.Second), "the exit of the victim", killHas("process.exit", vic.PID))

			if rs := killResponses(evs); len(rs) != 0 {
				t.Fatalf("no response.* event may exist without an active feature, got %s", rs[0].Line)
			}
			x := killEvs(evs, "process.exit", vic.PID)[0]
			if x.get("details.signal") != nil || x.num("details.exit_code") != 0 || x.get("details.response_action_id") != nil {
				t.Errorf("the victim exit: %v", x.get("details"))
			}
			if started := ofType(evs, "agent.started")[0]; started.get("details.kill.enabled") != false {
				t.Errorf("agent.started kill: %v", started.get("details.kill"))
			}
			if len(ofType(evs, "process.exec")) < 3 {
				t.Errorf("the observation must run as usual:\n%s", summarize(evs, 20))
			}
			st := killStop(t, a)
			if st.get("details.response") != nil {
				t.Errorf("agent.stopped reports response counters of a disabled feature: %v", st.get("details.response"))
			}
			for _, h := range ofType(a.Events(), "agent.health") {
				if h.get("details.response") != nil {
					t.Errorf("agent.health reports response counters of a disabled feature")
				}
			}
		})
	}
}

// ----------------------------------------------------------------------------
// 2. String and regex hit in a direct child

func TestKillStringAndRegexHitInDirectChild(t *testing.T) {
	cases := []struct {
		name string
		// rules returns the rules and the details.rules entry that must be reported.
		rules func(ke killEnv) (strs, regex []string, want string)
	}{
		{"string", func(ke killEnv) ([]string, []string, string) {
			s := ke.n("victim")
			return []string{s}, nil, killRuleKey("kill.strings[0]", "string", s, "image", -1)
		}},
		{"regex", func(ke killEnv) ([]string, []string, string) {
			re := "^(" + ke.n("victim") + "|" + ke.n("other") + ")$"
			return nil, []string{re}, killRuleKey("kill.regex[0]", "regex", re, "image", -1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ke := newKillEnv(t)
			strs, regex, rule := tc.rules(ke)
			a := killAgent(t, ke.cfg(strs, regex))
			d := newKillDir(t)
			root, tp := d.startK(kspec{Name: ke.root(), Kids: []kspec{{Name: ke.n("bystander")}, {Name: ke.n("victim")}}})
			by := tp.spawned(t, ke.n("bystander"))
			byStart, _ := killProcStart(by.PID)
			vic := tp.spawned(t, ke.n("victim"))

			requireKilled(t, tp.ended(t, vic.PID, killScale(20*time.Second)))
			evs := a.waitEvents(killScale(15*time.Second), "the audit pair and the exit of the victim",
				killAll(killHas("response.kill_result", vic.PID), killHas("process.exit", vic.PID)))

			w := ke.want(vic.PID, ke.n("victim"), root.PID)
			w.Rules = []string{rule}
			req, res := requireKillPair(t, evs, w)
			x := requireKillExit(t, evs, vic.PID, req.str("details.action_id"))
			// The decision was written before the process could have ended.
			if req.Seq() >= x.Seq() {
				t.Errorf("the decision #%d must precede the exit #%d", req.Seq(), x.Seq())
			}
			requireDecisions(t, evs, 1)
			if started := ofType(evs, "agent.started")[0]; started.get("details.kill.enabled") != true || started.num("details.kill.rules") != 1 {
				t.Errorf("agent.started kill: %v", started.get("details.kill"))
			}
			requireRunning(t, "the bystander", by.PID, byStart)
			requireNoAudit(t, evs, "the bystander", by.PID)
			requireNoAudit(t, evs, "the root", root.PID)

			// agent.health reports the action; so does agent.stopped.
			h := killHealthAfter(t, a, res.Seq())
			st := killStop(t, a)
			for _, ev := range []Ev{h, st} {
				requireCounter(t, ev, "rule_hits", 1)
				requireCounter(t, ev, "signal_attempts", 1)
				requireCounter(t, ev, "signals_accepted", 1)
				requireCounter(t, ev, "already_exited", 0)
				requireCounter(t, ev, "permission_denied", 0)
				requireCounter(t, ev, "errors", 0)
				requireCounter(t, ev, "dry_run", 0)
				requireCounter(t, ev, "latency_samples", 1)
			}
			requireCounter(t, h, "queue_len", 0)
			requireCounter(t, h, "queue_cap", 256)
			if lat := h.num("details.response.latency_max_ns"); lat <= 0 || lat >= int(10*time.Second) {
				t.Errorf("latency_max_ns %d", lat)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// 3. Grandchild and deeper

func TestKillGrandchildAndDeeper(t *testing.T) {
	ke := newKillEnv(t)
	victimRule := ke.n("victim")
	a := killAgent(t, ke.cfg([]string{victimRule}, nil))
	d := newKillDir(t)
	root, tp := d.startK(kspec{Name: ke.root(), Kids: []kspec{
		{Name: ke.n("bystander")},
		{Name: ke.n("mid1"), Kids: []kspec{
			{Name: ke.n("victim-a")},
			{Name: ke.n("mid2"), Kids: []kspec{
				{Name: ke.n("mid3"), Kids: []kspec{{Name: ke.n("victim-b")}}},
			}},
		}},
	}})
	mid1 := tp.spawned(t, ke.n("mid1"))
	mid2 := tp.spawned(t, ke.n("mid2"))
	mid3 := tp.spawned(t, ke.n("mid3"))
	va := tp.spawned(t, ke.n("victim-a"))
	vb := tp.spawned(t, ke.n("victim-b"))
	by := tp.spawned(t, ke.n("bystander"))
	byStart, _ := killProcStart(by.PID)

	requireKilled(t, tp.ended(t, va.PID, killScale(20*time.Second)))
	requireKilled(t, tp.ended(t, vb.PID, killScale(20*time.Second)))
	evs := a.waitEvents(killScale(15*time.Second), "both audit pairs and exits", killAll(
		killHas("response.kill_result", va.PID), killHas("process.exit", va.PID),
		killHas("response.kill_result", vb.PID), killHas("process.exit", vb.PID)))

	rule := killRuleKey("kill.strings[0]", "string", victimRule, "image", -1)
	for _, tc := range []struct {
		kid       killKid
		parent    killKid
		depth     int
		ancestors []int
	}{
		{va, mid1, 2, []int{root.PID, mid1.PID}},
		{vb, mid3, 4, []int{root.PID, mid1.PID, mid2.PID, mid3.PID}},
	} {
		w := ke.want(tc.kid.PID, tc.kid.Name, root.PID)
		w.ParentPID, w.Depth, w.Ancestors, w.Rules = tc.parent.PID, tc.depth, tc.ancestors, []string{rule}
		req, _ := requireKillPair(t, evs, w)
		requireKillExit(t, evs, tc.kid.PID, req.str("details.action_id"))
	}
	requireDecisions(t, evs, 2)
	for _, kid := range []killKid{mid1, mid2, mid3, by} {
		requireNoAudit(t, evs, kid.Name, kid.PID)
	}
	requireRunning(t, "the bystander", by.PID, byStart)
	st := killStop(t, a)
	requireCounter(t, st, "signal_attempts", 2)
	requireCounter(t, st, "signals_accepted", 2)
}

// ----------------------------------------------------------------------------
// 4. The watched root and processes outside of the watched trees

func TestKillNeverTouchesWatchedRootOrStrangers(t *testing.T) {
	ke := newKillEnv(t)
	// <token>-root-solo is a watched root that matches a rule and has no
	// children (a child inherits the image of its creator and would match, too).
	// <token>-stranger matches a rule and is no part of any watched tree.
	// <token>-victim below the watched root <token>-root proves that the rules
	// are active in this very run.
	solo, stranger, victim := ke.n("root-solo"), ke.n("stranger"), ke.n("victim")
	a := killAgent(t, ke.cfg([]string{solo, stranger, victim}, nil))
	d := newKillDir(t)
	soloP, _ := d.startK(kspec{Name: solo, LifeMS: 3000})
	outer, outerTap := d.startK(kspec{Name: ke.n("outer"), LifeMS: 3500, Kids: []kspec{{Name: stranger, LifeMS: 3000}}})
	strangerPID := outerTap.spawned(t, stranger).PID
	main, mainTap := d.startK(kspec{Name: ke.root(), LifeMS: 3500, Kids: []kspec{
		{Name: victim},
		{Name: ke.n("quiet"), LifeMS: 3000},
	}})
	vic := mainTap.spawned(t, victim)
	quiet := mainTap.spawned(t, ke.n("quiet"))
	requireKilled(t, mainTap.ended(t, vic.PID, killScale(20*time.Second)))
	requireEndedByItself(t, mainTap.ended(t, quiet.PID, killScale(20*time.Second)))
	requireEndedByItself(t, outerTap.ended(t, strangerPID, killScale(20*time.Second)))

	// Everything is over once the processes are gone and the agent saw their exits.
	soloP.wait(killScale(20 * time.Second))
	outer.wait(killScale(20 * time.Second))
	main.wait(killScale(20 * time.Second))
	evs := a.waitEvents(killScale(15*time.Second), "the exits of the roots", killAll(
		killHas("process.exit", soloP.PID), killHas("process.exit", main.PID), killHas("process.exit", quiet.PID)))

	for _, p := range []*prog{soloP, outer, main} {
		if p.state == nil || p.state.ExitCode() != 0 {
			t.Errorf("process %d must end by itself with exit status 0: %v", p.PID, p.state)
		}
	}
	x := killEvs(evs, "process.exit", soloP.PID)[0]
	if x.get("details.signal") != nil || x.num("details.exit_code") != 0 || x.get("details.response_action_id") != nil || x.Role() != "root" {
		t.Errorf("the watched root exit: %v", x.Raw)
	}
	requireNoAudit(t, evs, "the watched root that matches a rule", soloP.PID)
	requireNoAudit(t, evs, "the other watched root", main.PID)
	requireNoAudit(t, evs, "the process outside of every watched tree", strangerPID)
	requireNoAudit(t, evs, "the unwatched parent of the stranger", outer.PID)
	requireNoAudit(t, evs, "the quiet child", quiet.PID)
	if n := len(ofPID(evs, strangerPID)) + len(ofPID(evs, outer.PID)); n != 0 {
		t.Errorf("processes outside of every watched tree must not be observed at all, %d events", n)
	}
	requireDecisions(t, evs, 1) // only the control victim
	w := ke.want(vic.PID, victim, main.PID)
	w.Rules = []string{killRuleKey("kill.strings[2]", "string", victim, "image", -1)}
	req, _ := requireKillPair(t, evs, w)
	requireKillExit(t, evs, vic.PID, req.str("details.action_id"))
	st := killStop(t, a)
	requireCounter(t, st, "rule_hits", 1)
	requireCounter(t, st, "signal_attempts", 1)
}

// ----------------------------------------------------------------------------
// 5. Rules on arguments

func TestKillArgvRules(t *testing.T) {
	ke := newKillEnv(t)
	marker := ke.n("marker")
	a := killAgent(t, ke.cfg([]string{marker}, nil, func(c *agentCfg) {
		c.CaptureArgv = true
		c.KillFields = []string{"image", "argv"}
	}))
	d := newKillDir(t)
	// The marker is also in the arguments of the watched root: neither the root
	// (never a target) nor, through a cached copy of them, its children match.
	root, tp := d.startK(kspec{Name: ke.root(), Args: []string{marker + "-root"}, Kids: []kspec{
		{Name: ke.n("argchild"), Args: []string{"--note=" + marker + "-7", "plain"}},
		{Name: ke.n("argzero"), Argv: []string{marker + "-zero", "plain"}},
		{Name: ke.n("argother"), Args: []string{"something-else"}, LifeMS: 3000},
	}})
	child := tp.spawned(t, ke.n("argchild"))
	zero := tp.spawned(t, ke.n("argzero"))
	other := tp.spawned(t, ke.n("argother"))
	requireKilled(t, tp.ended(t, child.PID, killScale(20*time.Second)))
	requireKilled(t, tp.ended(t, zero.PID, killScale(20*time.Second)))
	requireEndedByItself(t, tp.ended(t, other.PID, killScale(20*time.Second)))
	evs := a.waitEvents(killScale(15*time.Second), "audit pairs and exits", killAll(
		killHas("response.kill_result", child.PID), killHas("process.exit", child.PID),
		killHas("response.kill_result", zero.PID), killHas("process.exit", zero.PID), killHas("process.exit", other.PID)))

	for _, tc := range []struct {
		kid   killKid
		arg   int // the argument that carries the marker
		argc  int
		argv0 string
	}{
		{child, 1, 3, filepath.Join(d.dir, ke.n("argchild"))}, // path, --note=<marker>-7, plain
		{zero, 0, 2, marker + "-zero"},                        // <marker>-zero, plain: argv[0] is an argument, too
	} {
		w := ke.want(tc.kid.PID, tc.kid.Name, root.PID)
		w.Rules = []string{killRuleKey("kill.strings[0]", "string", marker, "argv", tc.arg)}
		req, _ := requireKillPair(t, evs, w)
		requireKillExit(t, evs, tc.kid.PID, req.str("details.action_id"))
		exec := killEvs(evs, "process.exec", tc.kid.PID)[0]
		if argv := exec.argv(); len(argv) != tc.argc || argv[0] != tc.argv0 || !strings.Contains(argv[tc.arg], marker) {
			t.Errorf("%s: captured arguments %q", tc.kid.Name, argv)
		}
	}
	requireNoAudit(t, evs, "the child without the marker", other.PID)
	requireNoAudit(t, evs, "the watched root with the marker in its arguments", root.PID)
	requireDecisions(t, evs, 2)
	st := killStop(t, a)
	requireCounter(t, st, "signal_attempts", 2)
}

func TestKillArgvWithoutCaptureRefusesToStart(t *testing.T) {
	requireAgentBinary(t)
	ke := newKillEnv(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")
	yamlPath := filepath.Join(dir, "config.yaml")
	yaml := "config_version: 1\nwatch:\n  image_contains: " + yamlList([]string{ke.root()}) + "\nkill:\n  enabled: true\n  fields: [image, argv]\n  strings: " +
		yamlList([]string{ke.n("marker")}) + "\noutputs:\n  file:\n    path: " + strconv.Quote(logPath) + "\n"
	if err := os.WriteFile(yamlPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		path string // the configuration path the message must name
	}{
		{"yaml", []string{"--config", yamlPath}, "kill.fields[1]"},
		{"flags", []string{"--watch-image-contains", ke.root(), "--kill-enabled=true", "--kill-field", "argv", "--kill-string", ke.n("marker"), "--log-file", logPath}, "kill.fields[0]"},
		{"check-config", []string{"check-config", "--config", yamlPath}, "kill.fields[1]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := execCommand(agentBin, tc.args...)
			out, _ := cmd.CombinedOutput()
			if code := cmd.ProcessState.ExitCode(); code != 2 {
				t.Fatalf("exit code %d, want 2:\n%s", code, out)
			}
			for _, want := range []string{"capture.argv", tc.path} {
				if !strings.Contains(string(out), want) {
					t.Errorf("the message must name %q:\n%s", want, out)
				}
			}
			if _, err := os.Stat(logPath); err == nil {
				t.Fatal("a refused configuration must not create the log file")
			}
		})
	}
	// The same rules are fine once the capture is switched on explicitly (and
	// checking never signals or attaches anything).
	cmd := execCommand(agentBin, "check-config", "--config", yamlPath, "--capture-argv=true")
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "configuration OK") {
		t.Fatalf("check-config with capture.argv: %v\n%s", err, out)
	}
	if _, err := os.Stat(logPath); err == nil {
		t.Fatal("check-config created the log file")
	}
}

// ----------------------------------------------------------------------------
// 6. Exclusions and the reporting depth do not shield a target

func TestKillIndependentOfExclusionsAndDepth(t *testing.T) {
	// How the three normal events of the victim show up in the log. A fork child
	// carries the image of its creator, so an exclusion on the victim's own image
	// can only hit its exec and exit events, whereas the depth limit hides all.
	const (
		plain    = "plain"    // logged, not flagged
		excluded = "excluded" // logged, flagged as excluded
		absent   = "absent"   // not in the log
	)
	cases := []struct {
		name             string
		mod              func(ke killEnv, c *agentCfg)
		fork, exec, exit string
	}{
		{"exclusion, scope remote", func(ke killEnv, c *agentCfg) { c.ExcludeImage = []string{ke.n("victim")} }, plain, excluded, excluded},
		{"exclusion, scope all", func(ke killEnv, c *agentCfg) { c.ExcludeImage = []string{ke.n("victim")}; c.ExcludeScope = "all" }, plain, absent, absent},
		{"output depth", func(ke killEnv, c *agentCfg) { c.MaxDepth = 1 }, absent, absent, absent},
		{"exclusion and depth", func(ke killEnv, c *agentCfg) { c.ExcludeImage = []string{ke.n("victim")}; c.MaxDepth = 1 }, absent, absent, absent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ke := newKillEnv(t)
			victim, marker := ke.n("victim"), ke.n("marker")
			var sink *killSink
			mods := []func(*agentCfg){func(c *agentCfg) { tc.mod(ke, c) }}
			if killLoopbackWorks() {
				sink = newKillSink(t)
				mods = append(mods, func(c *agentCfg) { c.TCP = sink.Addr() })
			} else {
				t.Log("no TCP loopback in this environment: the remote output is not checked")
			}
			a := killAgent(t, ke.cfg([]string{victim}, nil, mods...))
			d := newKillDir(t)
			root, tp, ctl := d.startKControl(kspec{Name: ke.root()})
			tp.up(t, ke.root())
			ctl.spawn(kspec{Name: ke.n("bystander")})
			ctl.spawn(kspec{Name: ke.n("d1"), Kids: []kspec{{Name: ke.n("d2"), Kids: []kspec{{Name: victim}}}}})
			d1 := tp.spawned(t, ke.n("d1"))
			d2 := tp.spawned(t, ke.n("d2"))
			vic := tp.spawned(t, victim)
			by := tp.spawned(t, ke.n("bystander"))
			byStart, _ := killProcStart(by.PID)
			requireKilled(t, tp.ended(t, vic.PID, killScale(20*time.Second)))

			// A short lived marker process after the victim: its exit record follows
			// the records of the victim in the ring buffer, so once it is reported
			// (in the log and at the remote output) everything about the victim has
			// been processed, even where the victim itself is not reported.
			ctl.spawn(kspec{Name: marker, LifeMS: 50})
			mk := tp.spawned(t, marker)
			evs := a.waitEvents(killScale(15*time.Second), "the audit pair and the exit of the marker", killAll(killHas("response.kill_result", vic.PID), killHas("process.exit", mk.PID)))
			// ... and at the remote output, which gets the events in the same order.
			var remote []Ev
			if sink != nil {
				deadline := time.Now().Add(killScale(15 * time.Second))
				for {
					remote = sink.Events()
					if len(killEvs(remote, "process.exit", mk.PID)) > 0 && len(killEvs(remote, "response.kill_result", vic.PID)) > 0 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("the remote output did not get the exit of the marker and the audit result")
					}
					time.Sleep(25 * time.Millisecond)
				}
			}

			w := ke.want(vic.PID, victim, root.PID)
			w.ParentPID, w.Depth, w.Ancestors, w.InLog = d2.PID, 3, []int{root.PID, d1.PID, d2.PID}, tc.exec != absent
			w.Rules = []string{killRuleKey("kill.strings[0]", "string", victim, "image", -1)}
			req, res := requireKillPair(t, evs, w)
			if sup := req.get("filter.suppressed_outputs"); !reflect.DeepEqual(sup, []any{}) {
				t.Errorf("the audit event must go to every output: %v", sup)
			}

			// The normal events of the victim.
			for _, e := range []struct{ typ, want string }{
				{"process.fork", tc.fork}, {"process.exec", tc.exec}, {"process.exit", tc.exit},
			} {
				got := killEvs(evs, e.typ, vic.PID)
				if e.want == absent {
					if len(got) != 0 {
						t.Errorf("%s of the victim must not be in the log: %s", e.typ, got[0].Line)
					}
					continue
				}
				if len(got) != 1 {
					t.Errorf("%s of the victim: %d events, want 1", e.typ, len(got))
					continue
				}
				flagged, _ := got[0].get("filter.excluded").(bool)
				matches, _ := got[0].get("filter.matches").([]any)
				suppressed := got[0].get("filter.suppressed_outputs")
				switch e.want {
				case plain:
					if flagged || len(matches) != 0 || !reflect.DeepEqual(suppressed, []any{}) {
						t.Errorf("%s of the victim is not to be excluded: %v", e.typ, got[0].get("filter"))
					}
				case excluded:
					wantSuppressed := []any{} // the enabled remote outputs: none without a receiver
					if sink != nil {
						wantSuppressed = []any{"tcp"}
					}
					if !flagged || len(matches) != 1 || !reflect.DeepEqual(suppressed, wantSuppressed) {
						t.Errorf("%s of the victim must be flagged as excluded and held back from %v: %v", e.typ, wantSuppressed, got[0].get("filter"))
					}
				}
			}
			if tc.exit != absent {
				requireKillExit(t, evs, vic.PID, req.str("details.action_id"))
			}
			// The depth limit hides the deep processes only.
			if tc.name == "output depth" || tc.name == "exclusion and depth" {
				if len(killEvs(evs, "process.exec", d1.PID)) != 1 || len(killEvs(evs, "process.exec", d2.PID)) != 0 {
					t.Errorf("max_depth 1 must report the processes at depth 1 and nothing deeper")
				}
			}
			requireRunning(t, "the bystander", by.PID, byStart)

			// The remote output gets the audit events, byte for byte, even where the
			// normal events are held back.
			var gotReq, gotRes bool
			held := map[string]bool{"process.fork": tc.fork != plain, "process.exec": tc.exec != plain, "process.exit": tc.exit != plain}
			for _, e := range remote {
				switch {
				case e.str("event_id") == req.str("event_id"):
					gotReq = e.Line == req.Line
				case e.str("event_id") == res.str("event_id"):
					gotRes = e.Line == res.Line
				case e.PID() == vic.PID && held[e.Type()]:
					t.Errorf("an event of the victim that is excluded or too deep was delivered remotely: %s", e.Line)
				}
			}
			if sink != nil && (!gotReq || !gotRes) {
				t.Errorf("the remote output did not get both audit events unchanged (request %v, result %v)", gotReq, gotRes)
			}
			st := killStop(t, a)
			requireCounter(t, st, "signal_attempts", 1)
		})
	}
}

// ----------------------------------------------------------------------------
// 7. Several rules, one process generation, one attempt

func TestKillSeveralRulesOneAttempt(t *testing.T) {
	ke := newKillEnv(t)
	victim := ke.n("victim")
	prefix := ke.n("vic")
	a := killAgent(t, ke.cfg([]string{prefix, victim}, []string{"^" + victim + "$", "/" + victim + "$"}, func(c *agentCfg) {
		c.KillFields = []string{"image", "image_path"}
		c.Reconcile = "500ms"
	}))
	d := newKillDir(t)
	root, tp := d.startK(kspec{Name: ke.root(), Kids: []kspec{{Name: victim}}})
	vic := tp.spawned(t, victim)
	requireKilled(t, tp.ended(t, vic.PID, killScale(20*time.Second)))
	evs := a.waitEvents(killScale(15*time.Second), "the audit pair and the exit", killAll(killHas("response.kill_result", vic.PID), killHas("process.exit", vic.PID)))

	// Every rule that hits on every selected field is listed: 2 + 2 + 1 + 1.
	w := ke.want(vic.PID, victim, root.PID)
	w.Rules = []string{
		killRuleKey("kill.strings[0]", "string", prefix, "image", -1),
		killRuleKey("kill.strings[0]", "string", prefix, "image_path", -1),
		killRuleKey("kill.strings[1]", "string", victim, "image", -1),
		killRuleKey("kill.strings[1]", "string", victim, "image_path", -1),
		killRuleKey("kill.regex[0]", "regex", "^"+victim+"$", "image", -1),
		killRuleKey("kill.regex[1]", "regex", "/"+victim+"$", "image_path", -1),
	}
	req, _ := requireKillPair(t, evs, w)
	requireKillExit(t, evs, vic.PID, req.str("details.action_id"))
	if got := len(killRuleKeys(req)); got != 6 {
		t.Errorf("%d hits in the one action, want 6", got)
	}
	if path := killEvs(evs, "process.exec", vic.PID)[0].str("process.image_path"); !strings.HasSuffix(path, "/"+victim) {
		t.Errorf("image_path %q", path)
	}
	requireDecisions(t, evs, 1)
	st := killStop(t, a)
	requireCounter(t, st, "rule_hits", 1)
	requireCounter(t, st, "signal_attempts", 1)
	requireCounter(t, st, "signals_accepted", 1)
}

func TestKillExecChainIsJudgedAgain(t *testing.T) {
	t.Run("dry run: every exec once", func(t *testing.T) {
		// Dry run keeps the process alive, so the chain can go on and the
		// agent's reconciliations (every 500ms) see the same instance again and again.
		ke := newKillEnv(t)
		rule := ke.n("chain")
		a := killAgent(t, ke.cfg([]string{rule}, nil, func(c *agentCfg) {
			c.KillDryRun = true
			c.Reconcile = "500ms"
		}))
		d := newKillDir(t)
		root, tp := d.startK(kspec{Name: ke.root(), Kids: []kspec{
			{Name: ke.n("chain-a"), Chain: []string{ke.n("chain-b"), ke.n("chain-c")}, ChainDelayMS: 300, LifeMS: 3000},
		}})
		chain := tp.spawned(t, ke.n("chain-a"))
		requireEndedByItself(t, tp.ended(t, chain.PID, killScale(30*time.Second)))
		evs := a.waitEvents(killScale(15*time.Second), "the exit of the chain", killHas("process.exit", chain.PID))

		reqs, ress := killPairs(evs, chain.PID)
		if len(reqs) != 3 || len(ress) != 3 {
			t.Fatalf("%d decisions and %d results for three execs of one process, want 3 each:\n%s", len(reqs), len(ress), killDump(evs, chain.PID))
		}
		seen := map[int]bool{}
		images := map[int]string{1: ke.n("chain-a"), 2: ke.n("chain-b"), 3: ke.n("chain-c")}
		for _, req := range reqs {
			idx := req.num("details.exec_index")
			if seen[idx] || images[idx] == "" {
				t.Fatalf("exec_index %d decided twice or unexpected:\n%s", idx, killDump(evs, chain.PID))
			}
			seen[idx] = true
			var res Ev
			for _, r := range ress {
				if r.str("details.action_id") == req.str("details.action_id") {
					res = r
				}
			}
			if res.Raw == nil {
				t.Fatalf("no result for the decision of exec %d", idx)
			}
			w := ke.want(chain.PID, images[idx], root.PID)
			w.ExecIndex, w.Outcome, w.DryRun, w.Attempted = idx, "dry_run", true, false
			w.Rules = []string{killRuleKey("kill.strings[0]", "string", rule, "image", -1)}
			checkKillPair(t, evs, req, res, w)
			// The decision belongs to the exec of that generation.
			trig := filterEv(evs, func(e Ev) bool { return e.str("event_id") == req.str("details.trigger_event_id") })
			if len(trig) != 1 || trig[0].num("details.exec_index") != idx {
				t.Errorf("exec %d: the trigger event is %v", idx, trig)
			}
		}
		ids := map[string]bool{}
		for _, r := range reqs {
			ids[r.str("details.action_id")] = true
		}
		if len(ids) != 3 {
			t.Errorf("three execs, three different actions; got %d", len(ids))
		}
		if len(killEvs(evs, "process.discovered", chain.PID)) != 0 {
			t.Errorf("a reconciliation must not discover an instance that is already tracked")
		}
		requireDecisions(t, evs, 3)
		st := killStop(t, a)
		requireCounter(t, st, "rule_hits", 3)
		requireCounter(t, st, "dry_run", 3)
		requireCounter(t, st, "signal_attempts", 0)
	})

	t.Run("the second exec is the match", func(t *testing.T) {
		ke := newKillEnv(t)
		victim := ke.n("victim")
		a := killAgent(t, ke.cfg([]string{victim}, nil))
		d := newKillDir(t)
		root, tp := d.startK(kspec{Name: ke.root(), Kids: []kspec{
			{Name: ke.n("plain"), Chain: []string{victim}, ChainDelayMS: 300},
		}})
		proc := tp.spawned(t, ke.n("plain"))
		requireKilled(t, tp.ended(t, proc.PID, killScale(20*time.Second)))
		evs := a.waitEvents(killScale(15*time.Second), "the audit pair and the exit", killAll(killHas("response.kill_result", proc.PID), killHas("process.exit", proc.PID)))
		w := ke.want(proc.PID, victim, root.PID)
		w.ExecIndex = 2
		w.Rules = []string{killRuleKey("kill.strings[0]", "string", victim, "image", -1)}
		req, _ := requireKillPair(t, evs, w)
		requireKillExit(t, evs, proc.PID, req.str("details.action_id"))
		execs := killEvs(evs, "process.exec", proc.PID)
		if len(execs) != 2 || execs[1].str("details.previous_image") != ke.n("plain") || execs[0].Image() != ke.n("plain") {
			t.Errorf("the process executed %s, then %s: %d exec events", ke.n("plain"), victim, len(execs))
		}
		requireDecisions(t, evs, 1) // only the second exec
		killStop(t, a)
	})

	t.Run("the first exec is killed before the second", func(t *testing.T) {
		ke := newKillEnv(t)
		victim := ke.n("victim")
		a := killAgent(t, ke.cfg([]string{victim}, nil))
		d := newKillDir(t)
		root, tp := d.startK(kspec{Name: ke.root(), Kids: []kspec{
			{Name: victim, Chain: []string{ke.n("plain")}, ChainDelayMS: 4000},
		}})
		proc := tp.spawned(t, victim)
		requireKilled(t, tp.ended(t, proc.PID, killScale(20*time.Second)))
		evs := a.waitEvents(killScale(15*time.Second), "the audit pair and the exit", killAll(killHas("response.kill_result", proc.PID), killHas("process.exit", proc.PID)))
		w := ke.want(proc.PID, victim, root.PID)
		w.Rules = []string{killRuleKey("kill.strings[0]", "string", victim, "image", -1)}
		req, _ := requireKillPair(t, evs, w)
		requireKillExit(t, evs, proc.PID, req.str("details.action_id"))
		if got := kinds(ofPID(evs, proc.PID)); got != "fork,exec,exit" {
			t.Errorf("the process must be killed before its second exec: [%s]", got)
		}
		killStop(t, a)
	})
}

// ----------------------------------------------------------------------------
// 8. Parent excluded or already ended

func TestKillParentEndedOrExcluded(t *testing.T) {
	t.Run("the root has ended", func(t *testing.T) {
		ke := newKillEnv(t)
		victim := ke.n("victim")
		a := killAgent(t, ke.cfg([]string{victim}, nil))
		d := newKillDir(t)
		root, tp := d.startK(kspec{Name: ke.root(), Leave: true, Kids: []kspec{
			{Name: ke.n("orphan"), NoPdeath: true, AwaitOrphan: true, Kids: []kspec{{Name: victim}}},
		}})
		orphan := tp.spawned(t, ke.n("orphan"))
		vic := tp.spawned(t, victim)
		requireKilled(t, tp.ended(t, vic.PID, killScale(20*time.Second)))
		evs := a.waitEvents(killScale(15*time.Second), "the audit pair, the exit of the victim and of the root", killAll(
			killHas("response.kill_result", vic.PID), killHas("process.exit", vic.PID), killHas("process.exit", root.PID)))
		w := ke.want(vic.PID, victim, root.PID)
		w.ParentPID, w.Depth, w.Ancestors = orphan.PID, 2, []int{root.PID, orphan.PID}
		w.Rules = []string{killRuleKey("kill.strings[0]", "string", victim, "image", -1)}
		req, _ := requireKillPair(t, evs, w)
		requireKillExit(t, evs, vic.PID, req.str("details.action_id"))
		if rootExit := killEvs(evs, "process.exit", root.PID)[0]; rootExit.Seq() >= req.Seq() {
			t.Errorf("the root must have ended (#%d) before the grandchild was judged (#%d)", rootExit.Seq(), req.Seq())
		}
		killStop(t, a)
	})

	for _, scope := range []string{"remote", "all"} {
		t.Run("the parent is excluded, scope "+scope, func(t *testing.T) {
			ke := newKillEnv(t)
			victim, mid := ke.n("victim"), ke.n("mid")
			a := killAgent(t, ke.cfg([]string{victim}, nil, func(c *agentCfg) {
				c.ExcludeImage = []string{mid}
				c.ExcludeScope = scope
			}))
			d := newKillDir(t)
			root, tp := d.startK(kspec{Name: ke.root(), Kids: []kspec{{Name: mid, Kids: []kspec{{Name: victim}}}}})
			midKid := tp.spawned(t, mid)
			vic := tp.spawned(t, victim)
			requireKilled(t, tp.ended(t, vic.PID, killScale(20*time.Second)))
			evs := a.waitEvents(killScale(15*time.Second), "the audit pair and the exit of the victim", killAll(killHas("response.kill_result", vic.PID), killHas("process.exit", vic.PID)))
			w := ke.want(vic.PID, victim, root.PID)
			w.ParentPID, w.Depth, w.Ancestors = midKid.PID, 2, []int{root.PID, midKid.PID}
			w.Rules = []string{killRuleKey("kill.strings[0]", "string", victim, "image", -1)}
			req, _ := requireKillPair(t, evs, w)
			requireKillExit(t, evs, vic.PID, req.str("details.action_id"))
			midEvs := killEvs(evs, "process.exec", midKid.PID)
			switch scope {
			case "remote":
				if len(midEvs) != 1 || midEvs[0].get("filter.excluded") != true {
					t.Errorf("the excluded parent must be logged locally and flagged: %v", midEvs)
				}
			default:
				if len(midEvs) != 0 {
					t.Errorf("with scope all the excluded parent is not logged at all")
				}
			}
			if parent := req.str("parent.image"); parent != mid {
				t.Errorf("the audit event describes the excluded parent: parent.image %q", parent)
			}
			killStop(t, a)
		})
	}

	t.Run("the direct parent leaves", func(t *testing.T) {
		ke := newKillEnv(t)
		victim := ke.n("victim")
		a := killAgent(t, ke.cfg([]string{victim}, nil))
		d := newKillDir(t)
		root, tp := d.startK(kspec{Name: ke.root(), Kids: []kspec{
			{Name: ke.n("orphan"), NoPdeath: true, Leave: true, Kids: []kspec{{Name: victim, NoPdeath: true}}},
		}})
		orphan := tp.spawned(t, ke.n("orphan"))
		vic := tp.spawned(t, victim)
		// Nobody reports the end of the victim here; the kernel's exit record and /proc do.
		killWaitGone(t, "the victim", vic.PID, killScale(20*time.Second))
		evs := a.waitEvents(killScale(15*time.Second), "the audit pair and the exits", killAll(
			killHas("response.kill_result", vic.PID), killHas("process.exit", vic.PID), killHas("process.exit", orphan.PID)))
		w := ke.want(vic.PID, victim, root.PID)
		w.ParentPID, w.Depth, w.Ancestors = orphan.PID, 2, []int{root.PID, orphan.PID}
		w.Rules = []string{killRuleKey("kill.strings[0]", "string", victim, "image", -1)}
		req, _ := requireKillPair(t, evs, w)
		requireKillExit(t, evs, vic.PID, req.str("details.action_id"))
		killStop(t, a)
	})
}

// ----------------------------------------------------------------------------
// 9. A matching child that is alive when the agent starts

func TestKillAlreadyRunningChildAtStart(t *testing.T) {
	requireRoot(t)
	ke := newKillEnv(t)
	victim, deepVictim := ke.n("victim"), ke.n("victim-deep")
	d := newKillDir(t)
	root, tp := d.startK(kspec{Name: ke.root(), Kids: []kspec{
		{Name: ke.n("bystander")},
		{Name: victim},
		{Name: ke.n("mid"), Kids: []kspec{{Name: deepVictim}}},
	}})
	for _, n := range []string{ke.n("bystander"), victim, ke.n("mid"), deepVictim} {
		tp.up(t, n)
	}
	vic := tp.spawned(t, victim)
	mid := tp.spawned(t, ke.n("mid"))
	deep := tp.spawned(t, deepVictim)
	by := tp.spawned(t, ke.n("bystander"))
	byStart, _ := killProcStart(by.PID)
	for _, kid := range []killKid{vic, mid, deep, by} {
		if _, ok := killProcStart(kid.PID); !ok {
			t.Fatalf("%s must be running before the agent starts", kid.Name)
		}
	}

	// Nothing watches yet: only now the agent starts, with the kill rules.
	a := killAgent(t, ke.cfg([]string{victim}, nil))
	requireKilled(t, tp.ended(t, vic.PID, killScale(20*time.Second)))
	requireKilled(t, tp.ended(t, deep.PID, killScale(20*time.Second)))
	evs := a.waitEvents(killScale(15*time.Second), "both audit pairs and exits", killAll(
		killHas("response.kill_result", vic.PID), killHas("process.exit", vic.PID),
		killHas("response.kill_result", deep.PID), killHas("process.exit", deep.PID)))

	rule := killRuleKey("kill.strings[0]", "string", victim, "image", -1)
	for _, tc := range []struct {
		kid    killKid
		parent int
		depth  int
		anc    []int
	}{
		{vic, root.PID, 1, []int{root.PID}},
		{deep, mid.PID, 2, []int{root.PID, mid.PID}},
	} {
		w := ke.want(tc.kid.PID, tc.kid.Name, root.PID)
		w.ParentPID, w.Depth, w.Ancestors, w.ExecIndex, w.Trigger = tc.parent, tc.depth, tc.anc, 0, "process.discovered"
		w.Rules = []string{rule}
		req, _ := requireKillPair(t, evs, w)
		requireKillExit(t, evs, tc.kid.PID, req.str("details.action_id"))
		disc := killEvs(evs, "process.discovered", tc.kid.PID)
		if len(disc) != 1 || disc[0].str("details.discovery") != "startup" || disc[0].str("source") != "snapshot" || disc[0].Seq() >= req.Seq() {
			t.Errorf("%s: the decision belongs to its process.discovered event: %v", tc.kid.Name, disc)
		}
	}
	requireDecisions(t, evs, 2)
	for _, kid := range []killKid{mid, by} {
		requireNoAudit(t, evs, kid.Name, kid.PID)
	}
	requireRunning(t, "the bystander", by.PID, byStart)
	st := killStop(t, a)
	requireCounter(t, st, "signal_attempts", 2)
}

// ----------------------------------------------------------------------------
// 10. A short lived process

func TestKillShortLivedProcess(t *testing.T) {
	const n = 30
	ke := newKillEnv(t)
	useradd := ke.n("useradd")
	a := killAgent(t, ke.cfg(nil, []string{"^" + useradd + "$"}))
	d := newKillDir(t)
	root, tp := d.startK(kspec{Name: ke.root(), Rounds: n,
		Kids:   []kspec{{Name: ke.n("bystander")}},
		Serial: []kspec{{Name: useradd, Exit: true}},
	})
	by := tp.spawned(t, ke.n("bystander"))
	byStart, _ := killProcStart(by.PID)
	tp.await(t, killScale(120*time.Second), "all short lived processes", func(s string) bool { return strings.HasPrefix(s, "serial-done ") })

	kids := tp.started(useradd)
	if len(kids) != n {
		t.Fatalf("%d short lived processes started, want %d", len(kids), n)
	}
	evs := a.waitEvents(killScale(30*time.Second), "a result for every short lived process", func(evs []Ev) bool {
		for _, kid := range kids {
			if len(killEvs(evs, "response.kill_result", kid.PID)) == 0 || len(killEvs(evs, "process.exit", kid.PID)) == 0 {
				return false
			}
		}
		return true
	})

	counts := map[string]int{}
	for _, kid := range kids {
		end := tp.ended(t, kid.PID, killScale(20*time.Second))
		execs := killEvs(evs, "process.exec", kid.PID)
		if len(execs) != 1 {
			t.Fatalf("pid %d: %d exec events, want 1", kid.PID, len(execs))
		}
		reqs, ress := killPairs(evs, kid.PID)
		if len(reqs) != 1 || len(ress) != 1 {
			t.Fatalf("pid %d: %d decisions, %d results, want one each:\n%s", kid.PID, len(reqs), len(ress), killDump(evs, kid.PID))
		}
		res := ress[0]
		outcome := res.str("details.outcome")
		counts[outcome]++
		switch outcome {
		case "already_exited", "signal_sent":
		case "skipped":
			// The process ended, but was not yet reaped: a documented skip.
			if res.str("details.reason") != "identity_unverified" {
				t.Errorf("pid %d: skipped for %q", kid.PID, res.str("details.reason"))
			}
		default:
			t.Errorf("pid %d: outcome %q is not legal for a process that ended at once", kid.PID, outcome)
		}
		// The unmistakable identity: the audit events name the very instance
		// whose exec triggered them.
		for _, e := range []Ev{reqs[0], res} {
			if e.ID() != execs[0].ID() || e.str("process.start_boot_ns") != execs[0].str("process.start_boot_ns") || e.PID() != kid.PID || e.Image() != useradd {
				t.Errorf("pid %d: %s names %q (start %s), the exec event named %q (start %s)", kid.PID, e.Type(), e.ID(), e.str("process.start_boot_ns"),
					execs[0].ID(), execs[0].str("process.start_boot_ns"))
			}
		}
		if reqs[0].str("details.trigger_event_id") != execs[0].str("event_id") {
			t.Errorf("pid %d: the decision does not belong to the exec event", kid.PID)
		}
		// Only a process whose action said signal_sent can have been ended by a signal.
		if end.Signal != 0 && (end.Signal != 9 || outcome != "signal_sent") {
			t.Errorf("pid %d ended by signal %d although the outcome was %s", kid.PID, end.Signal, outcome)
		}
	}
	t.Logf("%d short lived processes: %v", n, counts)

	// Nobody else was signalled.
	for _, e := range killResponses(evs) {
		if e.Image() != useradd {
			t.Errorf("an audit event about %q: %s", e.Image(), e.Line)
		}
	}
	requireRunning(t, "the bystander", by.PID, byStart)
	requireNoAudit(t, evs, "the bystander", by.PID)
	requireNoAudit(t, evs, "the root", root.PID)
	if len(killEvs(evs, "process.exit", by.PID)) != 0 {
		t.Errorf("the bystander must not have ended")
	}

	st := killStop(t, a)
	requireCounter(t, st, "rule_hits", n)
	requireCounter(t, st, "signals_accepted", counts["signal_sent"])
	requireCounter(t, st, "already_exited", counts["already_exited"])
	requireCounter(t, st, "skipped.identity_unverified", counts["skipped"])
	// A signal that found the process gone is an attempt, too: the audit says which.
	requireCounter(t, st, "signal_attempts", killAttempts(evs))
}

// ----------------------------------------------------------------------------
// 10b. The agent is slower than the process: states that are otherwise a race

// killFreeze stops the agent (SIGSTOP). The kernel goes on collecting the
// records of everything that happens meanwhile, and the agent works through
// them, in order, when it continues. It makes "the process is already gone" and
// "the process executed something else in the meantime" deterministic.
func killFreeze(t *testing.T, a *agent) (thaw func()) {
	t.Helper()
	proc := a.cmd.Process
	var once sync.Once
	thaw = func() { once.Do(func() { _ = proc.Signal(syscall.SIGCONT) }) }
	t.Cleanup(thaw) // before the agent is asked to stop: a stopped process would not hear SIGTERM
	if err := proc.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(killScale(10 * time.Second))
	for {
		b, _ := os.ReadFile("/proc/" + strconv.Itoa(proc.Pid) + "/stat")
		if i := bytes.LastIndexByte(b, ')'); i >= 0 && i+2 < len(b) && b[i+2] == 'T' {
			return thaw
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent did not stop")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Processes that came and went while the agent was not looking: every
// decision finds the process gone. The outcome is already_exited, no signal is
// attempted, and the audit events still name the exact instance.
func TestKillProcessThatEndedBeforeTheAgentReacts(t *testing.T) {
	const n = 10
	ke := newKillEnv(t)
	useradd := ke.n("useradd")
	a := killAgent(t, ke.cfg(nil, []string{"^" + useradd + "$"}))
	d := newKillDir(t)
	root, tp, ctl := d.startKControl(kspec{Name: ke.root()})
	tp.up(t, ke.root())
	ctl.spawn(kspec{Name: ke.n("bystander")})
	by := tp.spawned(t, ke.n("bystander"))
	byStart, _ := killProcStart(by.PID)

	thaw := killFreeze(t, a)
	for i := 0; i < n; i++ {
		ctl.spawn(kspec{Name: useradd, Exit: true})
	}
	var kids []killKid
	deadline := time.Now().Add(killScale(30 * time.Second))
	for len(kids) < n || len(tp.with("child-ended name="+useradd+" ")) < n {
		if time.Now().After(deadline) {
			t.Fatalf("the short lived processes did not run:\n%s", tp.dump())
		}
		kids = tp.started(useradd)
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(ofType(a.Events(), "response.kill_requested")); n != 0 {
		t.Fatalf("the agent was meant to be stopped, yet it decided %d times", n)
	}
	thaw()

	evs := a.waitEvents(killScale(30*time.Second), "a result for every process", func(evs []Ev) bool {
		for _, kid := range kids {
			if len(killEvs(evs, "response.kill_result", kid.PID)) == 0 || len(killEvs(evs, "process.exit", kid.PID)) == 0 {
				return false
			}
		}
		return true
	})
	for _, kid := range kids {
		execs := killEvs(evs, "process.exec", kid.PID)
		if len(execs) != 1 {
			t.Fatalf("pid %d: %d exec events, want 1", kid.PID, len(execs))
		}
		w := ke.want(kid.PID, useradd, root.PID)
		w.Outcome, w.Attempted = "already_exited", false
		w.Rules = []string{killRuleKey("kill.regex[0]", "regex", "^"+useradd+"$", "image", -1)}
		req, res := requireKillPair(t, evs, w)
		if req.ID() != execs[0].ID() || res.str("process.start_boot_ns") != execs[0].str("process.start_boot_ns") {
			t.Errorf("pid %d: the audit events name %s, the exec event %s", kid.PID, res.ID(), execs[0].ID())
		}
		if req.str("details.trigger_event_id") != execs[0].str("event_id") {
			t.Errorf("pid %d: the decision does not belong to the exec event", kid.PID)
		}
		end := tp.ended(t, kid.PID, killScale(10*time.Second))
		requireEndedByItself(t, end) // nobody signalled it
		if x := killEvs(evs, "process.exit", kid.PID)[0]; x.get("details.signal") != nil {
			t.Errorf("pid %d: exit %v", kid.PID, x.get("details"))
		}
	}
	requireDecisions(t, evs, n)
	requireNoAudit(t, evs, "the bystander", by.PID)
	requireRunning(t, "the bystander", by.PID, byStart)
	h := killHealthAfter(t, a, ofType(evs, "response.kill_result")[n-1].Seq())
	requireCounter(t, h, "rule_hits", n)
	requireCounter(t, h, "already_exited", n)
	requireCounter(t, h, "signal_attempts", 0)
	requireCounter(t, h, "signals_accepted", 0)
	requireCounter(t, h, "errors", 0)
	killStop(t, a)
}

// A process that executed another program before the agent got to it is not
// killed for the old match: the decision for the first exec is skipped with a
// reason, the new program is judged by its own exec event (and matches nothing).
func TestKillInterveningExecIsNotKilledForAStaleMatch(t *testing.T) {
	ke := newKillEnv(t)
	victim, plain := ke.n("victim"), ke.n("plain")
	a := killAgent(t, ke.cfg([]string{victim}, nil))
	d := newKillDir(t)
	root, tp, ctl := d.startKControl(kspec{Name: ke.root()})
	tp.up(t, ke.root())

	thaw := killFreeze(t, a)
	// The victim becomes the plain program at once, which then stays for a while.
	ctl.spawn(kspec{Name: victim, Chain: []string{plain}, LifeMS: 3000})
	proc := tp.spawned(t, victim)
	tp.up(t, plain)
	thaw()

	evs := a.waitEvents(killScale(20*time.Second), "the result for the first exec", killHas("response.kill_result", proc.PID))
	w := ke.want(proc.PID, victim, root.PID)
	w.Outcome, w.Attempted, w.Reason = "skipped", false, "match_no_longer_verified"
	w.Rules = []string{killRuleKey("kill.strings[0]", "string", victim, "image", -1)}
	requireKillPair(t, evs, w)
	requireEndedByItself(t, tp.ended(t, proc.PID, killScale(20*time.Second)))
	evs = a.waitEvents(killScale(15*time.Second), "the exit of the process", killHas("process.exit", proc.PID))
	if execs := killEvs(evs, "process.exec", proc.PID); len(execs) != 2 || execs[0].Image() != victim || execs[1].Image() != plain {
		t.Errorf("the process executed %s, then %s: %d exec events", victim, plain, len(execs))
	}
	if x := killEvs(evs, "process.exit", proc.PID)[0]; x.get("details.signal") != nil || x.num("details.exit_code") != 0 {
		t.Errorf("the process must have ended by itself: %v", x.get("details"))
	}
	requireDecisions(t, evs, 1) // the new program matches nothing
	st := killStop(t, a)
	requireCounter(t, st, "rule_hits", 1)
	requireCounter(t, st, "skipped.match_no_longer_verified", 1)
	requireCounter(t, st, "signal_attempts", 0)
	requireCounter(t, st, "signals_accepted", 0)
}

// ----------------------------------------------------------------------------
// The agent itself is no target

// killInstall makes dst a copy (or hard link) of the executable src.
func killInstall(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.Link(src, dst); err == nil {
		return
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

// The agent is started as a child of the root it watches and a rule matches
// its own image: it must not kill itself, while another process that matches
// the same rule is killed.
func TestKillTheAgentIsNeverATarget(t *testing.T) {
	requireRoot(t)
	ke := newKillEnv(t)
	agentName, other := ke.n("agent"), ke.n("agent-b") // the rule <token>-agent matches both
	d := newKillDir(t)
	agentPath := filepath.Join(d.dir, agentName)
	killInstall(t, agentBin, agentPath)
	logPath := filepath.Join(d.dir, "events.jsonl")
	cfgPath := filepath.Join(d.dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(ke.cfg([]string{agentName}, nil).render(logPath)), 0o600); err != nil {
		t.Fatal(err)
	}
	events := func() []Ev {
		b, _ := os.ReadFile(logPath)
		return parseEvents(b)
	}
	waitLog := func(what string, cond func([]Ev) bool) []Ev {
		t.Helper()
		deadline := time.Now().Add(killScale(30 * time.Second))
		for {
			evs := events()
			if cond(evs) {
				return evs
			}
			if time.Now().After(deadline) {
				t.Fatalf("timeout waiting for %s:\n%s", what, summarize(evs, 30))
			}
			time.Sleep(25 * time.Millisecond)
		}
	}

	root, tp, ctl := d.startKControl(kspec{Name: ke.root()})
	tp.up(t, ke.root())
	ctl.spawn(kspec{Name: agentName, Argv: []string{agentPath, "--config", cfgPath}})
	ag := tp.spawned(t, agentName)
	evs := waitLog("the agent to be ready", func(evs []Ev) bool { return len(ofType(evs, "agent.ready")) > 0 })
	disc := killEvs(evs, "process.discovered", ag.PID)
	if len(disc) != 1 || disc[0].Role() != "descendant" || disc[0].Image() != agentName {
		t.Fatalf("the agent must have discovered itself as a descendant of the watched root: %v\n%s", disc, summarize(evs, 30))
	}

	// The rule is live: another process with a matching name is killed.
	ctl.spawn(kspec{Name: other})
	vic := tp.spawned(t, other)
	requireKilled(t, tp.ended(t, vic.PID, killScale(20*time.Second)))
	evs = waitLog("the audit pair of the other process", killAll(killHas("response.kill_result", vic.PID), killHas("process.exit", vic.PID)))
	w := ke.want(vic.PID, other, root.PID)
	w.Rules = []string{killRuleKey("kill.strings[0]", "string", agentName, "image", -1)}
	req, _ := requireKillPair(t, evs, w)
	requireKillExit(t, evs, vic.PID, req.str("details.action_id"))

	// The agent is still there, and never decided anything about itself.
	requireNoAudit(t, evs, "the agent itself", ag.PID)
	if _, ok := killProcStart(ag.PID); !ok {
		t.Fatalf("the agent must still be running")
	}
	requireDecisions(t, evs, 1)
	if err := syscall.Kill(ag.PID, syscall.SIGTERM); err != nil { // our own agent process
		t.Fatal(err)
	}
	end := tp.ended(t, ag.PID, killScale(20*time.Second))
	requireEndedByItself(t, end) // exit status 0 after SIGTERM
	evs = waitLog("agent.stopped", func(evs []Ev) bool { return len(ofType(evs, "agent.stopped")) > 0 })
	requireCounter(t, ofType(evs, "agent.stopped")[0], "rule_hits", 1)
	requireCounter(t, ofType(evs, "agent.stopped")[0], "signal_attempts", 1)
}

// ----------------------------------------------------------------------------
// 11. A cut value never produces a kill

func TestKillNeverOnTruncatedValue(t *testing.T) {
	ke := newKillEnv(t)
	// "useradd" of the scenario, with the token: the rule is ^<word>$ on argv.
	word := ke.n("useradd")
	a := killAgent(t, ke.cfg(nil, []string{"^" + word + "$"}, func(c *agentCfg) {
		c.CaptureArgv = true
		c.KillFields = []string{"argv"}
	}))
	d := newKillDir(t)
	filler := func(n int) string { return strings.Repeat("x", n) }
	// n arguments "a0".."a<n-1>" with the word at index at.
	many := func(n, at int) []string {
		argv := make([]string, n)
		for i := range argv {
			argv[i] = "a" + strconv.Itoa(i)
		}
		argv[at] = word
		return argv
	}
	// The kernel copies at most 4096 argument bytes, 32 arguments are kept.
	// With argv[0] of fcut bytes, its NUL and the word the copy ends at exactly
	// 4096 bytes: whatever follows the word is cut, the word itself loses its
	// terminator (the scenario of a 4088 byte argv[0] and "useradd").
	fcut := 4096 - 1 - len(word)
	victims := []struct {
		name      string
		argv      []string
		killed    bool
		arg       int  // the matching argument of a kill
		truncated bool // the capture of the exec is flagged as truncated
		captured  int  // number of complete arguments in the event
	}{
		// The copy ends right after the word: a cut argument without terminator.
		{ke.n("cut"), []string{filler(fcut), word + "-evil"}, false, -1, true, 1},
		// The argument is complete, but only its terminator is missing: not provable either.
		{ke.n("cutnul"), []string{filler(fcut), word}, false, -1, true, 1},
		// One byte less: the word and its terminator fit exactly. The control.
		{ke.n("complete"), []string{filler(fcut - 1), word}, true, 1, false, 2},
		// The matching argument is beyond the 32 captured ones.
		{ke.n("late40"), many(41, 40), false, -1, true, 32},
		// The last captured argument is complete and may match.
		{ke.n("last31"), many(45, 31), true, 31, true, 32},
	}
	var kids []kspec
	for _, v := range victims {
		k := kspec{Name: v.name, Argv: v.argv}
		if !v.killed {
			k.LifeMS = 3000
		}
		kids = append(kids, k)
	}
	kids = append(kids, kspec{Name: ke.n("bystander"), LifeMS: 3000})
	root, tp := d.startK(kspec{Name: ke.root(), Kids: kids})
	by := tp.spawned(t, ke.n("bystander"))

	pids := map[string]int{}
	for _, v := range victims {
		pids[v.name] = tp.spawned(t, v.name).PID
	}
	for _, v := range victims {
		end := tp.ended(t, pids[v.name], killScale(30*time.Second))
		if v.killed {
			requireKilled(t, end)
		} else {
			requireEndedByItself(t, end)
		}
	}
	requireEndedByItself(t, tp.ended(t, by.PID, killScale(30*time.Second)))
	evs := a.waitEvents(killScale(15*time.Second), "the exits of all processes", func(evs []Ev) bool {
		for _, v := range victims {
			if len(killEvs(evs, "process.exit", pids[v.name])) == 0 {
				return false
			}
		}
		return len(killEvs(evs, "process.exit", by.PID)) > 0
	})

	for _, v := range victims {
		pid := pids[v.name]
		exec := killEvs(evs, "process.exec", pid)
		if len(exec) != 1 {
			t.Fatalf("%s: %d exec events", v.name, len(exec))
		}
		// The test is only meaningful when the capture is cut where it was meant to be.
		if got := len(exec[0].argv()); got != v.captured {
			t.Errorf("%s: %d complete arguments captured, want %d (the cut is not where the test needs it)", v.name, got, v.captured)
		}
		cut := false
		if tf, _ := exec[0].get("data_quality.truncated_fields").([]any); len(tf) == 1 && tf[0] == "process.argv" {
			cut = true
		}
		if cut != v.truncated {
			t.Errorf("%s: truncated flag %v, want %v", v.name, cut, v.truncated)
		}
		if v.killed {
			w := ke.want(pid, v.name, root.PID)
			w.Rules = []string{killRuleKey("kill.regex[0]", "regex", "^"+word+"$", "argv", v.arg)}
			req, _ := requireKillPair(t, evs, w)
			requireKillExit(t, evs, pid, req.str("details.action_id"))
		} else {
			requireNoAudit(t, evs, v.name, pid)
			if x := killEvs(evs, "process.exit", pid)[0]; x.get("details.signal") != nil || x.num("details.exit_code") != 0 {
				t.Errorf("%s: exit %v", v.name, x.get("details"))
			}
		}
	}
	requireNoAudit(t, evs, "the bystander", by.PID)
	requireDecisions(t, evs, 2) // the two controls
	st := killStop(t, a)
	requireCounter(t, st, "rule_hits", 2)
	requireCounter(t, st, "signal_attempts", 2)
}

// ----------------------------------------------------------------------------
// 12. Dry run

func TestKillDryRun(t *testing.T) {
	ke := newKillEnv(t)
	victim := ke.n("victim")
	a := killAgent(t, ke.cfg([]string{victim}, nil, func(c *agentCfg) { c.KillDryRun = true }))
	d := newKillDir(t)
	root, tp := d.startK(kspec{Name: ke.root(), Kids: []kspec{{Name: victim, LifeMS: 2500}}})
	vic := tp.spawned(t, victim)
	// The victim ends by itself, with exit status 0, when no signal was sent.
	requireEndedByItself(t, tp.ended(t, vic.PID, killScale(30*time.Second)))
	evs := a.waitEvents(killScale(15*time.Second), "the audit pair and the exit", killAll(killHas("response.kill_result", vic.PID), killHas("process.exit", vic.PID)))
	w := ke.want(vic.PID, victim, root.PID)
	w.Outcome, w.DryRun, w.Attempted = "dry_run", true, false
	w.Rules = []string{killRuleKey("kill.strings[0]", "string", victim, "image", -1)}
	_, res := requireKillPair(t, evs, w)
	if x := killEvs(evs, "process.exit", vic.PID)[0]; x.get("details.signal") != nil || x.num("details.exit_code") != 0 {
		t.Errorf("the victim must have ended by itself: %v", x.get("details"))
	}
	if started := ofType(evs, "agent.started")[0]; started.get("details.kill.dry_run") != true {
		t.Errorf("agent.started kill: %v", started.get("details.kill"))
	}
	h := killHealthAfter(t, a, res.Seq())
	st := killStop(t, a)
	for _, ev := range []Ev{h, st} {
		requireCounter(t, ev, "rule_hits", 1)
		requireCounter(t, ev, "dry_run", 1)
		requireCounter(t, ev, "signal_attempts", 0)
		requireCounter(t, ev, "signals_accepted", 0)
		requireCounter(t, ev, "errors", 0)
		requireCounter(t, ev, "latency_samples", 0)
	}
}

// ----------------------------------------------------------------------------
// 13. Permission error

func TestKillPermissionDenied(t *testing.T) {
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Fatalf("this test needs setpriv (util-linux) to take CAP_KILL away from the agent: %v", err)
	}
	const nobody = 65534
	ke := newKillEnv(t)
	victim := ke.n("victim")
	cfg := ke.cfg([]string{victim}, nil)
	a := startAgentCustom(t, cfg.render, []string{"setpriv", "--bounding-set=-kill", "--inh-caps=-kill"})
	// The agent must really lack CAP_KILL (bit 5), else it could signal the victim.
	status, err := os.ReadFile("/proc/" + strconv.Itoa(a.cmd.Process.Pid) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if rest, ok := strings.CutPrefix(line, "CapEff:"); ok {
			caps, perr := strconv.ParseUint(strings.TrimSpace(rest), 16, 64)
			if perr != nil || caps&(1<<5) != 0 {
				t.Fatalf("the agent still has CAP_KILL (%s); setpriv did not remove it", line)
			}
		}
	}

	d := newSharedKillDir(t)
	root, tp, ctl := d.startKControl(kspec{Name: ke.root()})
	tp.up(t, ke.root())
	ctl.spawn(kspec{Name: victim, Cred: &kcred{Uid: nobody, Gid: nobody}, LifeMS: 3000})
	vic := tp.spawned(t, victim)
	evs := a.waitEvents(killScale(20*time.Second), "the result for the victim", killHas("response.kill_result", vic.PID))
	w := ke.want(vic.PID, victim, root.PID)
	w.Outcome, w.Errno = "permission_denied", "EPERM"
	w.Rules = []string{killRuleKey("kill.strings[0]", "string", victim, "image", -1)}
	req, res := requireKillPair(t, evs, w)
	h := killHealthAfter(t, a, res.Seq())
	requireCounter(t, h, "permission_denied", 1)
	requireCounter(t, h, "signal_attempts", 1)
	requireCounter(t, h, "signals_accepted", 0)
	if res.str("details.error.op") != "pidfd_send_signal" {
		t.Errorf("the denied call: %v", res.get("details.error"))
	}
	if uid := req.num("process.uid"); uid != nobody {
		t.Errorf("the victim runs as uid %d, want %d", uid, nobody)
	}

	// The agent goes on observing: a later process arrives (and is not a target).
	ctl.spawn(kspec{Name: ke.n("late"), LifeMS: 300})
	late := tp.spawned(t, ke.n("late"))
	evs = a.waitEvents(killScale(20*time.Second), "events of a process that started after the error", killHas("process.exit", late.PID))
	if len(killEvs(evs, "process.exec", late.PID)) != 1 {
		t.Errorf("the later process was not observed")
	}
	requireNoAudit(t, evs, "the later process", late.PID)

	// The victim lived on: it ends by itself.
	requireEndedByItself(t, tp.ended(t, vic.PID, killScale(30*time.Second)))
	requireDecisions(t, a.Events(), 1) // no retry
	st := killStop(t, a)
	requireCounter(t, st, "permission_denied", 1)
	requireCounter(t, st, "signal_attempts", 1)
	requireCounter(t, st, "signals_accepted", 0)
	requireCounter(t, st, "errors", 0)
}

// ----------------------------------------------------------------------------
// 14. File descriptor limit

func killOpenFDs(pid int) (lowestFree, count int, err error) {
	ents, err := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/fd")
	if err != nil {
		return 0, 0, err
	}
	used := map[int]bool{}
	for _, e := range ents {
		if n, err := strconv.Atoi(e.Name()); err == nil {
			used[n] = true
		}
	}
	for used[lowestFree] {
		lowestFree++
	}
	return lowestFree, len(used), nil
}

// killLowerFDLimit lowers the soft RLIMIT_NOFILE of a process to the number of
// its lowest free descriptor: its next open call fails with EMFILE. The
// returned function lifts the limit again; the end of the test does so, too.
func killLowerFDLimit(t *testing.T, pid int) (lift func()) {
	t.Helper()
	var orig unix.Rlimit
	if err := unix.Prlimit(pid, unix.RLIMIT_NOFILE, nil, &orig); err != nil {
		t.Fatalf("prlimit get: %v", err)
	}
	lift = func() {
		if err := unix.Prlimit(pid, unix.RLIMIT_NOFILE, &orig, nil); err != nil {
			t.Errorf("prlimit restore: %v", err)
		}
	}
	t.Cleanup(func() { _ = unix.Prlimit(pid, unix.RLIMIT_NOFILE, &orig, nil) })

	// A transient descriptor can only make a sample larger, so take the smallest.
	limit, open := -1, 0
	for i := 0; i < 5; i++ {
		lf, cnt, err := killOpenFDs(pid)
		if err != nil {
			t.Fatal(err)
		}
		if limit < 0 || lf < limit {
			limit, open = lf, cnt
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("the agent has %d descriptors open, the limit is lowered to %d (was %d)", open, limit, orig.Cur)
	if err := unix.Prlimit(pid, unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: uint64(limit), Max: orig.Max}, nil); err != nil {
		t.Fatalf("prlimit set: %v", err)
	}
	return lift
}

func TestKillFileDescriptorLimit(t *testing.T) {
	ke := newKillEnv(t)
	victim, victim2 := ke.n("victim"), ke.n("victim2")
	// No periodic reconciliation (it opens descriptors, too) disturbs the experiment.
	a := killAgent(t, ke.cfg([]string{victim}, nil, func(c *agentCfg) { c.Reconcile = "1h" }))
	d := newKillDir(t)
	root, tp, ctl := d.startKControl(kspec{Name: ke.root()})
	tp.up(t, ke.root())
	lift := killLowerFDLimit(t, a.cmd.Process.Pid)

	// 1. The victim cannot get a handle.
	ctl.spawn(kspec{Name: victim})
	v1 := tp.spawned(t, victim)
	evs := a.waitEvents(killScale(20*time.Second), "the result for the first victim", killHas("response.kill_result", v1.PID))
	rule := []string{killRuleKey("kill.strings[0]", "string", victim, "image", -1)}
	w1 := ke.want(v1.PID, victim, root.PID)
	w1.Outcome, w1.Attempted, w1.Errno, w1.Rules = "error", false, "EMFILE", rule
	_, res1 := requireKillPair(t, evs, w1)
	if res1.str("details.error.op") != "pidfd_open" {
		t.Errorf("the failing call: %v", res1.get("details.error"))
	}
	v1Start, running := killProcStart(v1.PID)
	if !running {
		t.Fatalf("the first victim must not have been signalled")
	}

	// 2. The limit is lifted. The failed action is not repeated, however long we wait.
	lift()
	h0 := len(ofType(evs, "agent.health"))
	evs = a.waitEvents(killScale(20*time.Second), "two health reports after the limit was lifted", func(evs []Ev) bool { return len(ofType(evs, "agent.health")) >= h0+2 })
	if n := len(killEvs(evs, "response.kill_requested", v1.PID)) + len(killEvs(evs, "response.kill_result", v1.PID)); n != 2 {
		t.Errorf("the first victim has %d audit events, want the pair only:\n%s", n, killDump(evs, v1.PID))
	}
	requireRunning(t, "the first victim", v1.PID, v1Start)

	// 3. The next victim is killed as usual.
	ctl.spawn(kspec{Name: victim2})
	v2 := tp.spawned(t, victim2)
	requireKilled(t, tp.ended(t, v2.PID, killScale(20*time.Second)))
	evs = a.waitEvents(killScale(15*time.Second), "the audit pair of the second victim", killAll(killHas("response.kill_result", v2.PID), killHas("process.exit", v2.PID)))
	w2 := ke.want(v2.PID, victim2, root.PID)
	w2.Rules = rule
	req2, res2 := requireKillPair(t, evs, w2)
	requireKillExit(t, evs, v2.PID, req2.str("details.action_id"))

	// Counters and audit agree: one real signal attempt, none for the failed open.
	attempted := killAttempts(evs)
	h := killHealthAfter(t, a, res2.Seq())
	requireCounter(t, h, "rule_hits", 2)
	requireCounter(t, h, "signal_attempts", attempted)
	requireCounter(t, h, "signal_attempts", 1)
	requireCounter(t, h, "signals_accepted", 1)
	requireCounter(t, h, "errors", 1)
	requireCounter(t, h, "queue_len", 0)
	requireCounter(t, h, "queue_cap", 256)
	st := killStop(t, a)
	requireCounter(t, st, "signal_attempts", 1)
	requireDecisions(t, a.Events(), 2) // one per victim
}

// A failed action is final for its exec generation, but the next exec of the
// same process instance is judged on its own (exec_index + 1) and its signal
// works as usual. This is the real signal variant of "an exec chain is judged
// again": without a failing first action the process would simply be dead
// before its second exec.
func TestKillFailedActionDoesNotBlockTheNextExec(t *testing.T) {
	ke := newKillEnv(t)
	first, second := ke.n("victim-a"), ke.n("victim-b") // both contain the rule <token>-victim
	rule := []string{killRuleKey("kill.strings[0]", "string", ke.n("victim"), "image", -1)}
	a := killAgent(t, ke.cfg([]string{ke.n("victim")}, nil, func(c *agentCfg) { c.Reconcile = "1h" }))
	d := newKillDir(t)
	root, tp, ctl := d.startKControl(kspec{Name: ke.root()})
	tp.up(t, ke.root())
	gate := filepath.Join(d.dir, "second-exec")
	lift := killLowerFDLimit(t, a.cmd.Process.Pid)

	// Exec 1 matches, but the agent cannot open a handle.
	ctl.spawn(kspec{Name: first, Chain: []string{second}, ChainWaitFile: gate})
	proc := tp.spawned(t, first)
	evs := a.waitEvents(killScale(20*time.Second), "the result for the first exec", killHas("response.kill_result", proc.PID))
	w1 := ke.want(proc.PID, first, root.PID)
	w1.Outcome, w1.Attempted, w1.Errno, w1.Rules = "error", false, "EMFILE", rule
	req1, res1 := requireKillPair(t, evs, w1)
	start, running := killProcStart(proc.PID)
	if !running {
		t.Fatal("the process must not have been signalled")
	}

	// The limit is lifted and the failed action stays what it is.
	lift()
	h0 := len(ofType(evs, "agent.health"))
	evs = a.waitEvents(killScale(20*time.Second), "two health reports after the limit was lifted", func(evs []Ev) bool { return len(ofType(evs, "agent.health")) >= h0+2 })
	if reqs, ress := killPairs(evs, proc.PID); len(reqs) != 1 || len(ress) != 1 {
		t.Errorf("the failed action was repeated: %d decisions, %d results", len(reqs), len(ress))
	}
	requireRunning(t, "the process", proc.PID, start)

	// Exec 2 of the same instance is judged by itself and killed.
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	requireKilled(t, tp.ended(t, proc.PID, killScale(20*time.Second)))
	evs = a.waitEvents(killScale(15*time.Second), "the second pair and the exit", func(evs []Ev) bool {
		reqs, ress := killPairs(evs, proc.PID)
		return len(reqs) == 2 && len(ress) == 2 && len(killEvs(evs, "process.exit", proc.PID)) > 0
	})
	reqs, ress := killPairs(evs, proc.PID)
	var req2, res2 Ev
	for _, r := range reqs {
		if r.num("details.exec_index") == 2 {
			req2 = r
			for _, s := range ress {
				if s.str("details.action_id") == r.str("details.action_id") {
					res2 = s
				}
			}
		}
	}
	if req2.Raw == nil || res2.Raw == nil {
		t.Fatalf("no decision for exec 2:\n%s", killDump(evs, proc.PID))
	}
	w2 := ke.want(proc.PID, second, root.PID)
	w2.ExecIndex, w2.Rules = 2, rule
	checkKillPair(t, evs, req2, res2, w2)
	if req2.str("details.action_id") == req1.str("details.action_id") || res2.Seq() <= res1.Seq() {
		t.Errorf("exec 2 needs an action of its own, after the first")
	}
	requireKillExit(t, evs, proc.PID, req2.str("details.action_id"))
	if execs := killEvs(evs, "process.exec", proc.PID); len(execs) != 2 || execs[1].num("details.exec_index") != 2 {
		t.Errorf("the process executed two programs: %d exec events", len(execs))
	}

	h := killHealthAfter(t, a, res2.Seq())
	requireCounter(t, h, "rule_hits", 2)
	requireCounter(t, h, "errors", 1)
	requireCounter(t, h, "signal_attempts", 1)
	requireCounter(t, h, "signals_accepted", 1)
	requireDecisions(t, a.Events(), 2)
	killStop(t, a)
}

// ----------------------------------------------------------------------------
// 15. Remote outage

func TestKillRemoteOutage(t *testing.T) {
	// A closed port: the agent must start, and the retries to deliver the audit
	// events must never delay or repeat an action.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()

	const victims = 3
	ke := newKillEnv(t)
	victim := ke.n("victim")
	a := killAgent(t, ke.cfg([]string{victim}, nil, func(c *agentCfg) {
		c.TCP = closed
		c.MaxRetries = 2
		c.ConnectTO = "300ms"
		c.WriteTO = "300ms"
		c.Health = "500ms"
	}))
	d := newKillDir(t)
	root, tp := d.startK(kspec{Name: ke.root(), Rounds: victims, DelayMS: 300, Serial: []kspec{{Name: victim}}})
	first := tp.spawned(t, victim)
	tp.await(t, killScale(15*time.Second), "the first victim to be killed (the kill must not wait for the remote output)", func(s string) bool {
		return strings.HasPrefix(s, "child-ended ") && intAfter(s, "pid") == first.PID
	})
	tp.await(t, killScale(60*time.Second), "all victims", func(s string) bool { return strings.HasPrefix(s, "serial-done ") })

	kids := tp.started(victim)
	if len(kids) != victims {
		t.Fatalf("%d victims started, want %d", len(kids), victims)
	}
	for _, kid := range kids {
		end := tp.ended(t, kid.PID, killScale(20*time.Second))
		requireKilled(t, end)
		// The retry cycle of one event takes seconds: a kill that waited for the
		// remote output would be seconds late, too.
		if took := time.Duration(end.T1 - kid.T0); took > 3*time.Second {
			t.Errorf("pid %d needed %s to end: the kill must not wait for the remote output", kid.PID, took)
		} else {
			t.Logf("pid %d ended %s after its start", kid.PID, took)
		}
	}

	// Wait until the remote output has really been retrying, then look at the counters.
	a.waitEvents(killScale(30*time.Second), "the failing remote output in agent.health", func(evs []Ev) bool {
		for _, h := range ofType(evs, "agent.health") {
			if h.num("details.outputs.tcp.retries") >= 1 && h.num("details.outputs.tcp.handed_over") == 0 {
				return true
			}
		}
		return false
	})
	evs := a.waitEvents(killScale(15*time.Second), "all audit pairs", func(evs []Ev) bool {
		for _, kid := range kids {
			if len(killEvs(evs, "response.kill_result", kid.PID)) == 0 || len(killEvs(evs, "process.exit", kid.PID)) == 0 {
				return false
			}
		}
		return true
	})
	for _, kid := range kids {
		w := ke.want(kid.PID, victim, root.PID)
		w.Rules = []string{killRuleKey("kill.strings[0]", "string", victim, "image", -1)}
		req, _ := requireKillPair(t, evs, w)
		requireKillExit(t, evs, kid.PID, req.str("details.action_id"))
	}
	requireDecisions(t, evs, victims)
	// agent.health: one signal attempt per action, however often the remote output retried.
	lastRes := ofType(evs, "response.kill_result")
	h := killHealthAfter(t, a, lastRes[len(lastRes)-1].Seq())
	requireCounter(t, h, "rule_hits", victims)
	requireCounter(t, h, "signal_attempts", victims)
	requireCounter(t, h, "signals_accepted", victims)
	if h.num("details.outputs.tcp.handed_over") != 0 {
		t.Errorf("the remote output was meant to be down: %v", h.get("details.outputs.tcp"))
	}
	st := killStop(t, a)
	requireCounter(t, st, "rule_hits", victims)
	requireCounter(t, st, "signal_attempts", victims)
	requireCounter(t, st, "signals_accepted", victims)
	if st.num("details.outputs.tcp.handed_over") != 0 || st.num("details.outputs.tcp.retries") < 1 {
		t.Errorf("the remote output was meant to be down: %v", st.get("details.outputs.tcp"))
	}
}

// ----------------------------------------------------------------------------
// 16. Reaction latency

// killStat is a summary of nanosecond values (nearest rank percentiles).
type killStat struct {
	Min int64 `json:"min_ns"`
	Avg int64 `json:"avg_ns"`
	P50 int64 `json:"p50_ns"`
	P95 int64 `json:"p95_ns"`
	P99 int64 `json:"p99_ns"`
	Max int64 `json:"max_ns"`
}

func killSummarize(v []int64) killStat {
	if len(v) == 0 {
		return killStat{}
	}
	s := append([]int64(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	var sum int64
	for _, x := range s {
		sum += x
	}
	rank := func(p float64) int64 { // nearest rank
		i := int(p*float64(len(s))+0.999999999) - 1
		return s[min(max(i, 0), len(s)-1)]
	}
	return killStat{Min: s[0], Avg: sum / int64(len(s)), P50: rank(0.50), P95: rank(0.95), P99: rank(0.99), Max: s[len(s)-1]}
}

func (s killStat) String() string {
	ms := func(ns int64) string { return fmt.Sprintf("%.3fms", float64(ns)/1e6) }
	return fmt.Sprintf("min %s avg %s p50 %s p95 %s p99 %s max %s", ms(s.Min), ms(s.Avg), ms(s.P50), ms(s.P95), ms(s.P99), ms(s.Max))
}

func TestKillReactionLatency(t *testing.T) {
	n := 100
	if testing.Short() {
		n = 20
	}
	if v, err := strconv.Atoi(os.Getenv("PW_E2E_KILL_N")); err == nil && v > 0 {
		n = v
	}
	// A short pause between the victims keeps the measurement about the reaction
	// to one process, not about a queue.
	gapMS := 20
	if v, err := strconv.Atoi(os.Getenv("PW_E2E_KILL_GAP_MS")); err == nil && v >= 0 {
		gapMS = v
	}

	ke := newKillEnv(t)
	victim := ke.n("victim")
	a := killAgent(t, ke.cfg([]string{victim}, nil, func(c *agentCfg) { c.Health = "5s" }))
	d := newKillDir(t)
	ttl := int(killScale(time.Duration(n)*3*time.Second+time.Minute) / time.Millisecond)
	_, tp := d.startK(kspec{Name: ke.root(), Rounds: n, DelayMS: gapMS, TTLMS: ttl, Serial: []kspec{{Name: victim, TTLMS: ttl}}})
	tp.await(t, time.Duration(n)*killScale(3*time.Second)+time.Minute, "all victims", func(s string) bool { return strings.HasPrefix(s, "serial-done ") })

	kids := tp.started(victim)
	if len(kids) != n {
		t.Fatalf("%d victims started, want %d", len(kids), n)
	}
	evs := a.waitEvents(killScale(60*time.Second), "an audit result for every victim", func(evs []Ev) bool {
		return len(ofType(evs, "response.kill_result")) >= n
	})

	var attempt, decision, extCreator, extTest []int64
	for _, kid := range kids {
		end := tp.ended(t, kid.PID, killScale(30*time.Second))
		if end.Signal != int(syscall.SIGKILL) {
			t.Errorf("victim %d was not killed: %s", kid.PID, end.Line)
			continue
		}
		reqs, ress := killPairs(evs, kid.PID)
		if len(reqs) != 1 || len(ress) != 1 {
			t.Errorf("victim %d: %d decisions and %d results", kid.PID, len(reqs), len(ress))
			continue
		}
		res := ress[0]
		if res.str("details.outcome") != "signal_sent" {
			t.Errorf("victim %d: outcome %s", kid.PID, res.str("details.outcome"))
			continue
		}
		al, ok1 := killNS(res, "details.attempt_latency_ns")
		dl, ok2 := killNS(res, "details.decision_latency_ns")
		if !ok1 || !ok2 {
			t.Errorf("victim %d: latencies %v %v", kid.PID, res.get("details.attempt_latency_ns"), res.get("details.decision_latency_ns"))
			continue
		}
		ec, et := end.T1-kid.T0, end.At.UnixNano()-kid.T0
		for _, v := range []struct {
			what string
			ns   int64
		}{{"attempt_latency_ns", al}, {"decision_latency_ns", dl}, {"external (creator clock)", ec}, {"external (test clock)", et}} {
			if v.ns <= 0 || v.ns >= int64(10*time.Second) {
				t.Errorf("victim %d: %s = %d ns, want between 0 and 10 s", kid.PID, v.what, v.ns)
			}
		}
		attempt, decision, extCreator, extTest = append(attempt, al), append(decision, dl), append(extCreator, ec), append(extTest, et)
	}
	if len(attempt) != n {
		t.Fatalf("only %d of %d victims could be measured", len(attempt), n)
	}
	sa, sd, sc, st := killSummarize(attempt), killSummarize(decision), killSummarize(extCreator), killSummarize(extTest)
	t.Logf("N=%d sequential victims, %d ms apart", n, gapMS)
	t.Logf("attempt_latency_ns   (exec record in the kernel -> signal attempt): %s", sa)
	t.Logf("decision_latency_ns  (exec record in the kernel -> decision):       %s", sd)
	t.Logf("external, creator clock (start returned -> wait returned):          %s", sc)
	t.Logf("external, test clock    (start returned -> line read by the test):  %s", st)

	stopped := killStop(t, a)
	requireCounter(t, stopped, "signal_attempts", n)
	requireCounter(t, stopped, "signals_accepted", n)
	t.Logf("agent.stopped response: latency_samples %d avg %d ns max %d ns", stopped.num("details.response.latency_samples"),
		stopped.num("details.response.latency_avg_ns"), stopped.num("details.response.latency_max_ns"))

	if dir := os.Getenv("PW_E2E_REPORT_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
		report := map[string]any{
			"test":                      "TestKillReactionLatency",
			"n":                         n,
			"gap_ms":                    gapMS,
			"kernel":                    strings.TrimSpace(string(kernel)),
			"goarch":                    runtime.GOARCH,
			"attempt_latency_ns":        sa,
			"decision_latency_ns":       sd,
			"external_creator_clock_ns": sc,
			"external_test_clock_ns":    st,
			"time":                      time.Now().UTC().Format(time.RFC3339),
			"note": "attempt/decision latency are measured from the kernel's exec record; external is measured from the return of the creator's " +
				"start call to the return of its wait call (creator clock) or to the line being read by the test (test clock)",
		}
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "kill-latency.json")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("report written to %s", path)
	}
}

// ----------------------------------------------------------------------------
// Additional scenarios

// A fork child inherits the image of its creator and is a real new instance of
// the tree: a rule on the image of the watched root hits it at process.fork,
// while the root itself is never a target.
func TestKillOnForkWithInheritedImage(t *testing.T) {
	ke := newKillEnv(t)
	rootName := ke.n("root-fork")
	a := killAgent(t, ke.cfg(nil, []string{"^" + rootName + "$"}))
	d := newKillDir(t)
	root, tp := d.startK(kspec{Name: rootName, ForkHold: true})
	child := tp.spawned(t, rootName+"-fork")
	requireKilled(t, tp.ended(t, child.PID, killScale(20*time.Second)))
	evs := a.waitEvents(killScale(15*time.Second), "the audit pair and the exit", killAll(killHas("response.kill_result", child.PID), killHas("process.exit", child.PID)))
	w := ke.want(child.PID, rootName, root.PID)
	w.RootImage, w.ExecIndex, w.Trigger = rootName, 0, "process.fork"
	w.Rules = []string{killRuleKey("kill.regex[0]", "regex", "^"+rootName+"$", "image", -1)}
	req, _ := requireKillPair(t, evs, w)
	requireKillExit(t, evs, child.PID, req.str("details.action_id"))
	if got := req.str("process.image_state"); got != "inherited" {
		t.Errorf("image_state %q, want inherited", got)
	}
	root.wait(killScale(20 * time.Second))
	if root.state == nil || root.state.ExitCode() != 0 {
		t.Errorf("the watched root must end by itself: %v", root.state)
	}
	requireNoAudit(t, a.Events(), "the watched root", root.PID)
	killStop(t, a)
}

// The documented priority: defaults < YAML < explicit flags. A list flag
// replaces the YAML list, a boolean flag overrides the YAML value, a single
// empty value clears a list.
func TestKillConfigPriority(t *testing.T) {
	t.Run("a list flag replaces the YAML list", func(t *testing.T) {
		ke := newKillEnv(t)
		victim, bystander := ke.n("victim"), ke.n("bystander")
		a := startAgentCustom(t, ke.cfg([]string{bystander}, nil).render, nil, "--kill-string", victim)
		d := newKillDir(t)
		root, tp := d.startK(kspec{Name: ke.root(), Kids: []kspec{{Name: victim}, {Name: bystander, LifeMS: 2500}}})
		vic := tp.spawned(t, victim)
		by := tp.spawned(t, bystander)
		requireKilled(t, tp.ended(t, vic.PID, killScale(20*time.Second)))
		requireEndedByItself(t, tp.ended(t, by.PID, killScale(20*time.Second)))
		evs := a.waitEvents(killScale(15*time.Second), "the audit pair", killAll(killHas("response.kill_result", vic.PID), killHas("process.exit", by.PID)))
		w := ke.want(vic.PID, victim, root.PID)
		w.Rules = []string{killRuleKey("kill.strings[0]", "string", victim, "image", -1)}
		requireKillPair(t, evs, w)
		requireNoAudit(t, evs, "the child the YAML list named", by.PID)
		killStop(t, a)
	})
	t.Run("a boolean flag overrides the YAML value", func(t *testing.T) {
		ke := newKillEnv(t)
		victim := ke.n("victim")
		disabled := func(p string) string {
			return agentCfg{Watch: []string{ke.root()}}.render(p) + "kill:\n  enabled: false\n  fields: [image]\n  strings: " + yamlList([]string{victim}) + "\n  regex: []\n"
		}
		a := startAgentCustom(t, disabled, nil, "--kill-enabled=true")
		d := newKillDir(t)
		root, tp := d.startK(kspec{Name: ke.root(), Kids: []kspec{{Name: victim}}})
		vic := tp.spawned(t, victim)
		requireKilled(t, tp.ended(t, vic.PID, killScale(20*time.Second)))
		evs := a.waitEvents(killScale(15*time.Second), "the audit pair", killHas("response.kill_result", vic.PID))
		w := ke.want(vic.PID, victim, root.PID)
		w.Rules = []string{killRuleKey("kill.strings[0]", "string", victim, "image", -1)}
		requireKillPair(t, evs, w)
		killStop(t, a)
	})
	t.Run("an empty value clears the list", func(t *testing.T) {
		requireAgentBinary(t)
		ke := newKillEnv(t)
		dir := t.TempDir()
		logPath := filepath.Join(dir, "events.jsonl")
		cfgPath := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(cfgPath, []byte(ke.cfg([]string{ke.n("victim")}, nil).render(logPath)), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := execCommand(agentBin, "--config", cfgPath, "--kill-string=")
		out, _ := cmd.CombinedOutput()
		if code := cmd.ProcessState.ExitCode(); code != 2 || !strings.Contains(string(out), "kill.enabled") {
			t.Fatalf("exit code %d, want 2 and a message about the missing rule:\n%s", code, out)
		}
		if _, err := os.Stat(logPath); err == nil {
			t.Fatal("a refused configuration must not create the log file")
		}
	})
}
