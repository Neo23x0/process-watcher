//go:build linux

// Package integration runs the real agent binary against real processes on a
// real kernel and checks the JSONL it writes. Nothing is mocked: the tests need
// root and the initial PID namespace (a privileged container with --pid=host,
// or a VM; see tests/vm).
//
// The test binary is also the controlled process under test: it is hard
// linked under names like pwtest-nginx and re-executes itself in a helper
// mode (PW_E2E_HELPER), so the image name of every process is known and no
// shell helpers are involved.
package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
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

var (
	selfExe  string
	agentBin string
)

func TestMain(m *testing.M) {
	if mode := os.Getenv("PW_E2E_HELPER"); mode != "" {
		helperMain(mode, os.Args[1:])
		return
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot find the test binary:", err)
		os.Exit(2)
	}
	selfExe = exe
	agentBin = os.Getenv("PW_AGENT_BIN")
	if agentBin == "" {
		agentBin = filepath.Join(filepath.Dir(exe), "process-watcher")
	}
	os.Exit(m.Run())
}

// requireAgentBinary is for tests that run the agent binary without needing
// root (configuration errors, check-config, print-config). A plain
// `go test ./...` has no agent binary: those tests skip, as the privileged
// ones do. With PW_AGENT_BIN set, a missing file is an error.
func requireAgentBinary(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(agentBin); err != nil {
		if os.Getenv("PW_AGENT_BIN") == "" {
			t.Skip("no agent binary: build ./cmd/process-watcher and set PW_AGENT_BIN (see tools/ci/kernel-tests.sh)")
		}
		t.Fatalf("agent binary not found (PW_AGENT_BIN): %v", err)
	}
}

// requireRoot skips a test where the agent cannot run.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the integration tests need root and the initial PID namespace")
	}
	requireAgentBinary(t)
}

// ----------------------------------------------------------------------------
// Events

// Ev is one parsed JSONL event with path based access.
type Ev struct {
	Raw  map[string]any
	Line string
}

func (e Ev) get(path string) any {
	var cur any = e.Raw
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

func (e Ev) str(path string) string {
	if s, ok := e.get(path).(string); ok {
		return s
	}
	return ""
}

func (e Ev) num(path string) int {
	if f, ok := e.get(path).(float64); ok {
		return int(f)
	}
	return -1
}

func (e Ev) Type() string  { return e.str("event_type") }
func (e Ev) PID() int      { return e.num("process.pid") }
func (e Ev) Image() string { return e.str("process.image") }
func (e Ev) ID() string    { return e.str("process.process_id") }
func (e Ev) Role() string  { return e.str("lineage.role") }
func (e Ev) Depth() int    { return e.num("lineage.depth") }
func (e Ev) RootPID() int  { return e.num("root.pid") }
func (e Ev) Seq() int      { return e.num("sequence") }

func (e Ev) argv() []string {
	arr, _ := e.get("process.argv").([]any)
	var out []string
	for _, a := range arr {
		if s, ok := a.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func parseEvents(b []byte) []Ev {
	var evs []Ev
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		line := sc.Text()
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			evs = append(evs, Ev{Raw: m, Line: line})
		}
	}
	return evs
}

func filterEv(evs []Ev, f func(Ev) bool) []Ev {
	var out []Ev
	for _, e := range evs {
		if f(e) {
			out = append(out, e)
		}
	}
	return out
}

func ofType(evs []Ev, typ string) []Ev {
	return filterEv(evs, func(e Ev) bool { return e.Type() == typ })
}

func ofPID(evs []Ev, pid int) []Ev {
	return filterEv(evs, func(e Ev) bool { return e.PID() == pid && strings.HasPrefix(e.Type(), "process.") })
}

func kinds(evs []Ev) string {
	var k []string
	for _, e := range evs {
		k = append(k, strings.TrimPrefix(e.Type(), "process."))
	}
	return strings.Join(k, ",")
}

// ----------------------------------------------------------------------------
// Agent

// agentCfg is rendered to the YAML file the agent is started with.
type agentCfg struct {
	Watch        []string
	ExcludeImage []string
	ExcludeArgv  []string
	ExcludeScope string
	CaptureArgv  bool
	MaxDepth     int
	KillEnabled  bool
	KillDryRun   bool
	KillFields   []string
	KillStrings  []string
	KillRegex    []string
	TCP          string
	UDP          string
	UDPMaxBytes  int
	WebhookURL   string
	QueueSize    int
	MaxRetries   int
	RotateMB     int
	KeepFiles    int
	RingMB       int
	MaxProcesses int
	Reconcile    string
	Health       string
	ConnectTO    string
	WriteTO      string
}

func yamlList(l []string) string {
	var q []string
	for _, s := range l {
		q = append(q, strconv.Quote(s))
	}
	return "[" + strings.Join(q, ", ") + "]"
}

func (c agentCfg) render(logPath string) string {
	var b strings.Builder
	b.WriteString("config_version: 1\n")
	fmt.Fprintf(&b, "watch:\n  image_contains: %s\n", yamlList(c.Watch))
	if c.MaxDepth > 0 {
		fmt.Fprintf(&b, "  max_depth: %d\n", c.MaxDepth)
	}
	if len(c.ExcludeImage) > 0 || len(c.ExcludeArgv) > 0 || c.ExcludeScope != "" {
		b.WriteString("exclude:\n")
		if len(c.ExcludeImage) > 0 {
			fmt.Fprintf(&b, "  image_contains: %s\n", yamlList(c.ExcludeImage))
		}
		if len(c.ExcludeArgv) > 0 {
			fmt.Fprintf(&b, "  argv_contains: %s\n", yamlList(c.ExcludeArgv))
		}
		if c.ExcludeScope != "" {
			fmt.Fprintf(&b, "  scope: %s\n", c.ExcludeScope)
		}
	}
	if c.CaptureArgv {
		b.WriteString("capture:\n  argv: true\n")
	}
	if c.KillEnabled {
		fmt.Fprintf(&b, "kill:\n  enabled: true\n  dry_run: %v\n", c.KillDryRun)
		fields := c.KillFields
		if len(fields) == 0 {
			fields = []string{"image"}
		}
		fmt.Fprintf(&b, "  fields: %s\n  strings: %s\n  regex: %s\n", yamlList(fields), yamlList(c.KillStrings), yamlList(c.KillRegex))
	}
	b.WriteString("outputs:\n  file:\n")
	fmt.Fprintf(&b, "    path: %s\n", strconv.Quote(logPath))
	if c.RotateMB > 0 {
		fmt.Fprintf(&b, "    rotate_size_mb: %d\n", c.RotateMB)
	}
	if c.KeepFiles > 0 {
		fmt.Fprintf(&b, "    keep_files: %d\n", c.KeepFiles)
	}
	if c.TCP != "" {
		fmt.Fprintf(&b, "  tcp:\n    address: %s\n", strconv.Quote(c.TCP))
	}
	if c.UDP != "" {
		fmt.Fprintf(&b, "  udp:\n    address: %s\n", strconv.Quote(c.UDP))
		if c.UDPMaxBytes > 0 {
			fmt.Fprintf(&b, "    max_bytes: %d\n", c.UDPMaxBytes)
		}
	}
	if c.WebhookURL != "" {
		fmt.Fprintf(&b, "  webhook:\n    url: %s\n", strconv.Quote(c.WebhookURL))
	}
	if c.QueueSize > 0 || c.ConnectTO != "" || c.WriteTO != "" || c.MaxRetries > 0 {
		b.WriteString("delivery:\n")
		if c.QueueSize > 0 {
			fmt.Fprintf(&b, "  queue_size: %d\n", c.QueueSize)
		}
		if c.ConnectTO != "" {
			fmt.Fprintf(&b, "  connect_timeout: %s\n", c.ConnectTO)
		}
		if c.WriteTO != "" {
			fmt.Fprintf(&b, "  write_timeout: %s\n", c.WriteTO)
		}
		if c.MaxRetries > 0 {
			fmt.Fprintf(&b, "  max_retries: %d\n", c.MaxRetries)
		}
	}
	b.WriteString("runtime:\n")
	health, reconcile := c.Health, c.Reconcile
	if health == "" {
		health = "1s"
	}
	if reconcile == "" {
		reconcile = "2s"
	}
	fmt.Fprintf(&b, "  health_interval: %s\n  reconcile_interval: %s\n", health, reconcile)
	if c.RingMB > 0 {
		fmt.Fprintf(&b, "  ring_buffer_mb: %d\n", c.RingMB)
	}
	if c.MaxProcesses > 0 {
		fmt.Fprintf(&b, "  max_processes: %d\n", c.MaxProcesses)
	}
	b.WriteString("  shutdown_timeout: 5s\n")
	return b.String()
}

// copyExecutable copies the program src to dst so that every user can run it.
func copyExecutable(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		return err
	}
	return os.Chmod(dst, 0o755) // the umask may have narrowed the mode
}

// agent is a running agent process.
type agent struct {
	t       *testing.T
	cmd     *exec.Cmd
	bin     string // the program to start; empty: agentBin
	cwd     string // its working directory; empty: that of the test
	dir     string
	LogPath string
	CfgPath string
	stderr  *syncBuf
	done    chan struct{}
	exit    int
	once    sync.Once
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// startAgent writes the configuration, starts the agent and waits for
// agent.ready. The agent is stopped (SIGTERM) when the test ends.
func startAgent(t *testing.T, cfg agentCfg) *agent {
	t.Helper()
	requireRoot(t)
	dir := t.TempDir()
	a := &agent{t: t, dir: dir, LogPath: filepath.Join(dir, "events.jsonl"), CfgPath: filepath.Join(dir, "config.yaml"), stderr: &syncBuf{}}
	if err := os.WriteFile(a.CfgPath, []byte(cfg.render(a.LogPath)), 0o600); err != nil {
		t.Fatal(err)
	}
	a.launch([]string{"--config", a.CfgPath}, nil)
	a.waitReady(20 * time.Second)
	return a
}

func (a *agent) launch(args []string, cred *syscall.Credential) {
	bin := a.bin
	if bin == "" {
		bin = agentBin
	}
	a.cmd = exec.Command(bin, args...)
	a.cmd.Dir = a.cwd
	a.cmd.Stderr = a.stderr
	if cred != nil {
		a.cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	if err := a.cmd.Start(); err != nil {
		a.t.Fatalf("start agent: %v", err)
	}
	a.done = make(chan struct{})
	go func() {
		err := a.cmd.Wait()
		a.exit = a.cmd.ProcessState.ExitCode()
		_ = err
		close(a.done)
	}()
	a.t.Cleanup(func() { a.Stop() })
}

func (a *agent) waitReady(timeout time.Duration) {
	a.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(ofType(a.Events(), "agent.ready")) > 0 {
			return
		}
		select {
		case <-a.done:
			a.t.Fatalf("agent exited with %d before it was ready:\n%s", a.exit, a.stderr.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	a.t.Fatalf("agent not ready after %s:\n%s", timeout, a.stderr.String())
}

// Events reads everything the agent has written so far (all rotated files too,
// oldest first).
func (a *agent) Events() []Ev {
	var all []byte
	var archives []string
	for i := 1; ; i++ {
		p := a.LogPath + "." + strconv.Itoa(i)
		if _, err := os.Stat(p); err != nil {
			break
		}
		archives = append(archives, p)
	}
	for i := len(archives) - 1; i >= 0; i-- {
		b, _ := os.ReadFile(archives[i])
		all = append(all, b...)
	}
	b, _ := os.ReadFile(a.LogPath)
	return parseEvents(append(all, b...))
}

// Stop sends SIGTERM and waits for the exit. It returns the exit code.
func (a *agent) Stop() int {
	a.once.Do(func() {
		if a.cmd == nil || a.cmd.Process == nil {
			return
		}
		select {
		case <-a.done:
			return
		default:
		}
		_ = a.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-a.done:
		case <-time.After(20 * time.Second):
			_ = a.cmd.Process.Kill()
			<-a.done
		}
	})
	<-a.done
	return a.exit
}

// waitEvents polls the log until cond holds.
func (a *agent) waitEvents(timeout time.Duration, what string, cond func([]Ev) bool) []Ev {
	a.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		evs := a.Events()
		if cond(evs) {
			return evs
		}
		if time.Now().After(deadline) {
			a.t.Fatalf("timeout waiting for %s after %s; %d events so far:\n%s", what, timeout, len(evs), summarize(evs, 40))
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func summarize(evs []Ev, max int) string {
	var b strings.Builder
	start := 0
	if len(evs) > max {
		start = len(evs) - max
	}
	for _, e := range evs[start:] {
		fmt.Fprintf(&b, "  #%d %s pid=%d image=%s\n", e.Seq(), e.Type(), e.PID(), e.Image())
	}
	return b.String()
}

// ----------------------------------------------------------------------------
// Controlled processes

// progDir creates a directory with hard links of the test binary under the
// given names; running such a link makes that name the process' image.
type progDir struct {
	t   *testing.T
	dir string
}

func newProgDir(t *testing.T, names ...string) *progDir {
	t.Helper()
	d := &progDir{t: t, dir: t.TempDir()}
	for _, n := range names {
		d.add(n)
	}
	return d
}

var linkMu sync.Mutex

func (d *progDir) add(name string) string {
	linkMu.Lock()
	defer linkMu.Unlock()
	p := filepath.Join(d.dir, name)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if err := os.Link(selfExe, p); err != nil {
		// Another file system: copy to a temporary name and rename, so no
		// process ever executes a file that is still being written.
		b, rerr := os.ReadFile(selfExe)
		if rerr != nil {
			d.t.Fatal(rerr)
		}
		tmp := p + ".tmp"
		if werr := os.WriteFile(tmp, b, 0o755); werr != nil {
			d.t.Fatal(werr)
		}
		if werr := os.Rename(tmp, p); werr != nil {
			d.t.Fatal(werr)
		}
	}
	return p
}

// prog is a started controlled process; its stdout lines are collected.
type prog struct {
	t     *testing.T
	cmd   *exec.Cmd
	PID   int
	lines chan string
	done  chan struct{}
	state *os.ProcessState
}

// start runs <dir>/<name> in the given helper mode.
func (d *progDir) start(name, mode string, args ...string) *prog {
	d.t.Helper()
	return d.startEnv(name, mode, nil, args...)
}

// startEnv is start with additional environment variables.
func (d *progDir) startEnv(name, mode string, env []string, args ...string) *prog {
	d.t.Helper()
	path := d.add(name)
	cmd := exec.Command(path, args...)
	cmd.Env = append(append(os.Environ(), "PW_E2E_HELPER="+mode, "PW_E2E_DIR="+d.dir), env...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		d.t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		d.t.Fatalf("start %s: %v", name, err)
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
		_ = syscall.Kill(-p.PID, syscall.SIGKILL)
		_ = cmd.Process.Kill()
	})
	return p
}

// waitLine returns the first line with the prefix (earlier lines are skipped).
func (p *prog) waitLine(prefix string, timeout time.Duration) string {
	p.t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case l, ok := <-p.lines:
			if !ok {
				p.t.Fatalf("process %d ended before printing %q", p.PID, prefix)
			}
			if strings.HasPrefix(l, prefix) {
				return l
			}
		case <-deadline:
			p.t.Fatalf("process %d did not print %q within %s", p.PID, prefix, timeout)
		}
	}
}

// collect returns all lines with the prefix until the process ended.
func (p *prog) collect(prefix string, timeout time.Duration) []string {
	p.t.Helper()
	var out []string
	deadline := time.After(timeout)
	for {
		select {
		case l, ok := <-p.lines:
			if !ok {
				return out
			}
			if strings.HasPrefix(l, prefix) {
				out = append(out, l)
			}
		case <-deadline:
			p.t.Fatalf("process %d still running after %s", p.PID, timeout)
		}
	}
}

func (p *prog) wait(timeout time.Duration) {
	p.t.Helper()
	select {
	case <-p.done:
	case <-time.After(timeout):
		p.t.Fatalf("process %d did not end within %s", p.PID, timeout)
	}
}

// intAfter parses "key=123" lines.
func intAfter(line, key string) int {
	for _, f := range strings.Fields(line) {
		if v, ok := strings.CutPrefix(f, key+"="); ok {
			n, _ := strconv.Atoi(v)
			return n
		}
	}
	return -1
}

func strAfter(line, key string) string {
	for _, f := range strings.Fields(line) {
		if v, ok := strings.CutPrefix(f, key+"="); ok {
			return v
		}
	}
	return ""
}

// execCommand creates a command for synchronous use with CombinedOutput; the
// ProcessState is available afterwards.
func execCommand(name string, args ...string) *exec.Cmd { return exec.Command(name, args...) }
