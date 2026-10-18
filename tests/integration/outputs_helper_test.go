//go:build linux

package integration

// Helpers of the output scenarios (outputs_test.go): a configuration renderer
// that can express every setting of the outputs, receivers for TCP (plain and
// TLS), UDP and the webhook that record what they get, a small PKI, helpers to
// read the agent's log and to compare it with what the receivers got, and a
// helper mode of the test binary that produces bursts of short lived processes
// with arguments of a chosen size. Every top level name starts with "out".

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// outToken makes the program names and the watch pattern of one test unique on
// the machine. Other test suites may run on the same kernel at the same time,
// and a watch pattern is a substring match of the image name: with a random
// token in both, an agent only ever sees the processes of its own test.
type outToken string

func outNewToken() outToken {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return outToken(hex.EncodeToString(b[:]))
}

// Prefix is the watch pattern: every program of the test starts with it.
func (k outToken) Prefix() string { return "pwo" + string(k) }

// Root is the name of the program that is the root of the observed tree.
func (k outToken) Root() string { return k.Prefix() + "-root" }

// Name returns the name of another program of the test.
func (k outToken) Name(role string) string { return k.Prefix() + "-" + role }

// ----------------------------------------------------------------------------
// Helper mode: bursts of short lived children

func init() {
	extraHelpers["out-burst"] = outBurstMain
}

// outBurstMain is the helper mode "out-burst". Arguments (all optional):
//
//	n=<children> arg=<bytes of one argument> par=<parallel workers>
//
// It runs /bin/true that many times and prints "child pid=<pid>" for each of
// them, "done n=<n>" at the end. With arg=0 the children get no argument.
func outBurstMain(args []string) {
	n, argBytes, par := 100, 0, 1
	for _, a := range args {
		k, v, _ := strings.Cut(a, "=")
		x, _ := strconv.Atoi(v)
		switch k {
		case "n":
			n = x
		case "arg":
			argBytes = x
		case "par":
			par = max(x, 1)
		}
	}
	say("up pid=%d name=%s ppid=%d", os.Getpid(), baseName(), os.Getppid())
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < par; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= n {
					return
				}
				var cargs []string
				if argBytes > 0 {
					cargs = []string{outPad(i, argBytes)}
				}
				c := exec.Command("/bin/true", cargs...)
				if err := c.Run(); err != nil {
					fmt.Fprintln(os.Stderr, "out-burst:", err)
					os.Exit(1)
				}
				say("child pid=%d", c.ProcessState.Pid())
			}
		}()
	}
	wg.Wait()
	say("done n=%d", n)
}

// outPad returns a printable ASCII argument of exactly size bytes.
func outPad(i, size int) string {
	prefix := fmt.Sprintf("pad%06d-", i)
	if size <= len(prefix) {
		return prefix[:size]
	}
	return prefix + strings.Repeat("x", size-len(prefix))
}

// outBurst starts the burst helper under the given program name.
func (d *progDir) outBurst(name string, n, argBytes, par int) *prog {
	d.t.Helper()
	return d.start(name, "out-burst", "n="+strconv.Itoa(n), "arg="+strconv.Itoa(argBytes), "par="+strconv.Itoa(par))
}

// outBurstDone waits until the burst ended and returns the PIDs of the children.
func outBurstDone(t *testing.T, p *prog, timeout time.Duration) []int {
	t.Helper()
	var pids []int
	for _, l := range p.collect("child ", timeout) {
		pids = append(pids, intAfter(l, "pid"))
	}
	return pids
}

// ----------------------------------------------------------------------------
// Configuration and agent start

// outCfg is rendered to the YAML file of an agent. Zero values leave the
// built-in default in place.
type outCfg struct {
	Token        outToken // watch pattern: Token.Prefix() unless Watch is set
	Watch        []string
	ExcludeImage []string
	ExcludeArgv  []string
	ExcludeScope string
	CaptureArgv  bool
	ArgvMaxArgs  int // capture.argv_max_args; 0: the default
	ArgvMaxBytes int // capture.argv_max_bytes; 0: the default

	LogPath      string // default: <dir>/events.jsonl
	RotateMB     int
	KeepFiles    int
	SyncInterval string

	TCP        string
	TLS        bool
	CAFile     string
	ServerName string

	UDP    string
	UDPMax int

	Webhook        string
	TokenEnv       string
	WebhookTimeout string

	QueueSize  int
	ConnectTO  string
	WriteTO    string
	MaxRetries *int // nil: default (5)

	Health    string // default 1s
	Reconcile string // default 10s
	Shutdown  string // default 10s
	RingMB    int    // 0: the default (16)
}

// outInt returns a pointer to n (for outCfg.MaxRetries, where 0 is a value).
func outInt(n int) *int { return &n }

func (c outCfg) render(logPath string) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	watch := c.Watch
	if len(watch) == 0 {
		if c.Token == "" {
			panic("outCfg needs a Token or a Watch list")
		}
		watch = []string{c.Token.Prefix()}
	}
	w("config_version: 1\nwatch:\n  image_contains: %s\n", yamlList(watch))
	if len(c.ExcludeImage) > 0 || len(c.ExcludeArgv) > 0 || c.ExcludeScope != "" {
		w("exclude:\n")
		if len(c.ExcludeImage) > 0 {
			w("  image_contains: %s\n", yamlList(c.ExcludeImage))
		}
		if len(c.ExcludeArgv) > 0 {
			w("  argv_contains: %s\n", yamlList(c.ExcludeArgv))
		}
		if c.ExcludeScope != "" {
			w("  scope: %s\n", c.ExcludeScope)
		}
	}
	if c.CaptureArgv {
		w("capture:\n  argv: true\n")
		if c.ArgvMaxArgs > 0 {
			w("  argv_max_args: %d\n", c.ArgvMaxArgs)
		}
		if c.ArgvMaxBytes > 0 {
			w("  argv_max_bytes: %d\n", c.ArgvMaxBytes)
		}
	}
	w("outputs:\n  file:\n    path: %s\n", strconv.Quote(logPath))
	if c.RotateMB > 0 {
		w("    rotate_size_mb: %d\n", c.RotateMB)
	}
	if c.KeepFiles > 0 {
		w("    keep_files: %d\n", c.KeepFiles)
	}
	if c.SyncInterval != "" {
		w("    sync_interval: %s\n", c.SyncInterval)
	}
	if c.TCP != "" {
		w("  tcp:\n    address: %s\n", strconv.Quote(c.TCP))
		if c.TLS {
			w("    tls: true\n")
		}
		if c.CAFile != "" {
			w("    ca_file: %s\n", strconv.Quote(c.CAFile))
		}
		if c.ServerName != "" {
			w("    server_name: %s\n", strconv.Quote(c.ServerName))
		}
	}
	if c.UDP != "" {
		w("  udp:\n    address: %s\n", strconv.Quote(c.UDP))
		if c.UDPMax > 0 {
			w("    max_bytes: %d\n", c.UDPMax)
		}
	}
	if c.Webhook != "" {
		w("  webhook:\n    url: %s\n", strconv.Quote(c.Webhook))
		if c.TokenEnv != "" {
			w("    token_env: %s\n", strconv.Quote(c.TokenEnv))
		}
		if c.WebhookTimeout != "" {
			w("    timeout: %s\n", c.WebhookTimeout)
		}
	}
	if c.QueueSize > 0 || c.ConnectTO != "" || c.WriteTO != "" || c.MaxRetries != nil {
		w("delivery:\n")
		if c.QueueSize > 0 {
			w("  queue_size: %d\n", c.QueueSize)
		}
		if c.ConnectTO != "" {
			w("  connect_timeout: %s\n", c.ConnectTO)
		}
		if c.WriteTO != "" {
			w("  write_timeout: %s\n", c.WriteTO)
		}
		if c.MaxRetries != nil {
			w("  max_retries: %d\n", *c.MaxRetries)
		}
	}
	health, reconcile, shutdown := c.Health, c.Reconcile, c.Shutdown
	if health == "" {
		health = "1s"
	}
	if reconcile == "" {
		reconcile = "10s"
	}
	if shutdown == "" {
		shutdown = "10s"
	}
	w("runtime:\n  health_interval: %s\n  reconcile_interval: %s\n  shutdown_timeout: %s\n", health, reconcile, shutdown)
	if c.RingMB > 0 {
		w("  ring_buffer_mb: %d\n", c.RingMB)
	}
	return b.String()
}

// outShutdownLimit remembers the shutdown_timeout each agent was configured with.
var outShutdownLimit sync.Map // *agent -> time.Duration

// outLaunch writes the configuration into a fresh directory and starts the
// agent without waiting for it. The harness stops it (SIGTERM) when the test
// ends; if the test failed, the agent's stderr is printed.
func outLaunch(t *testing.T, cfg outCfg) *agent {
	t.Helper()
	requireRoot(t)
	dir := t.TempDir()
	logPath := cfg.LogPath
	if logPath == "" {
		logPath = filepath.Join(dir, "events.jsonl")
	}
	a := &agent{t: t, dir: dir, LogPath: logPath, CfgPath: filepath.Join(dir, "config.yaml"), stderr: &syncBuf{}}
	if err := os.WriteFile(a.CfgPath, []byte(cfg.render(logPath)), 0o600); err != nil {
		t.Fatal(err)
	}
	limit := cfg.Shutdown
	if limit == "" {
		limit = "10s"
	}
	if d, err := time.ParseDuration(limit); err == nil {
		outShutdownLimit.Store(a, d)
	}
	a.launch([]string{"--config", a.CfgPath}, nil)
	t.Cleanup(func() {
		outShutdownLimit.Delete(a)
		if t.Failed() {
			t.Logf("agent stderr:\n%s", a.stderr.String())
		}
	})
	return a
}

// outStart is outLaunch followed by waiting for agent.ready. (With a log that
// already holds an agent.ready of an earlier run, use outLaunch and wait for the
// new one.)
func outStart(t *testing.T, cfg outCfg) *agent {
	t.Helper()
	a := outLaunch(t, cfg)
	a.waitReady(30 * time.Second)
	return a
}

// outWait polls cond until it holds.
func outWait(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout after %s waiting for %s", timeout, what)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// outSettle waits until count has stopped growing for 400ms (at most limit).
func outSettle(t *testing.T, count func() int, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	last, since := count(), time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
		if n := count(); n != last {
			last, since = n, time.Now()
		} else if time.Since(since) >= 400*time.Millisecond {
			return
		}
	}
}

// outWaitDatagrams waits until the UDP receiver has want datagrams. UDP may
// lose datagrams, so it also returns once nothing new arrived for two seconds
// and never fails: the callers compare what they got with what they expect.
func outWaitDatagrams(u *outUDPServer, want int, limit time.Duration) {
	deadline := time.Now().Add(limit)
	last, since := u.Count(), time.Now()
	for u.Count() < want && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		if n := u.Count(); n != last {
			last, since = n, time.Now()
		} else if time.Since(since) > 2*time.Second {
			return
		}
	}
}

// outRunAgent runs the agent binary to its end; it is expected to refuse or
// fail at once. A run that does not end is killed and fails the test.
func outRunAgent(t *testing.T, env []string, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, agentBin, args...)
	if env != nil {
		cmd.Env = env
	}
	out, _ := cmd.CombinedOutput()
	if ctx.Err() != nil || cmd.ProcessState == nil {
		t.Fatalf("the agent did not end within 30s (did it start observing?):\n%s", out)
	}
	return cmd.ProcessState.ExitCode(), string(out)
}

// outLoopbackWorks reports whether a TCP connection to 127.0.0.1 succeeds.
// With the loopback interface down, binding the address still works but
// connecting to it fails with "network is unreachable".
func outLoopbackWorks() bool {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer ln.Close()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// outEnsureLoopback makes sure that 127.0.0.1 can be used. A test VM that
// boots without an init system has the loopback interface down; it is brought
// up in that case, which is what any init system does first. In a normal
// system or container nothing is changed.
func outEnsureLoopback(t *testing.T) {
	t.Helper()
	if outLoopbackWorks() {
		return
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("127.0.0.1 is not usable and no socket can be created: %v", err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		t.Fatalf("127.0.0.1 is not usable and the loopback interface cannot be inspected: %v", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		t.Fatalf("127.0.0.1 is not usable and the loopback interface cannot be brought up: %v", err)
	}
	if !outLoopbackWorks() {
		t.Fatal("127.0.0.1 is still not usable after the loopback interface was brought up")
	}
	t.Log("the loopback interface was down; it has been brought up for the tests")
}

// ----------------------------------------------------------------------------
// Reading the log

// outCount returns a numeric detail of an event, 0 if it is absent (counters
// that are zero may be omitted from the output).
func outCount(e Ev, path string) int {
	if n := e.num(path); n > 0 {
		return n
	}
	return 0
}

// outOutput returns details.outputs.<output>.<key> of a health or stopped event.
func outOutput(e Ev, output, key string) int {
	return outCount(e, "details.outputs."+output+"."+key)
}

// outRemoteEvents returns the events a remote output was offered: everything
// except agent.stopped (stored locally only) and events the exclusions keep
// away from the remote outputs.
func outRemoteEvents(evs []Ev) []Ev {
	return filterEv(evs, func(e Ev) bool {
		return e.Type() != "agent.stopped" && e.get("filter.excluded") != true
	})
}

func outByID(evs []Ev) map[string]Ev {
	m := make(map[string]Ev, len(evs))
	for _, e := range evs {
		m[e.str("event_id")] = e
	}
	return m
}

func outIDs(evs []Ev) []string {
	ids := make([]string, len(evs))
	for i, e := range evs {
		ids[i] = e.str("event_id")
	}
	return ids
}

// outEventID returns the event_id of a JSONL line ("" if it is not JSON).
func outEventID(line []byte) string {
	var h struct {
		EventID string `json:"event_id"`
	}
	if json.Unmarshal(line, &h) != nil {
		return ""
	}
	return h.EventID
}

// outAssertIdentical checks that every received line is exactly one complete
// JSON line, ends in a single newline and is byte-identical to the log line
// with the same event_id. It returns how often each event_id was received.
func outAssertIdentical(t *testing.T, what string, got [][]byte, byID map[string]Ev) map[string]int {
	t.Helper()
	return outCompareLines(t, what, got, byID, false)
}

// outCompareLines is outAssertIdentical; with allowUnknown, lines whose
// event_id is not in byID (events that were rotated out of the log) are
// counted but not reported.
func outCompareLines(t *testing.T, what string, got [][]byte, byID map[string]Ev, allowUnknown bool) map[string]int {
	t.Helper()
	count := make(map[string]int, len(got))
	bad := 0
	report := func(format string, a ...any) {
		bad++
		if bad <= 5 {
			t.Errorf(what+": "+format, a...)
		}
	}
	for i, l := range got {
		if len(l) == 0 || l[len(l)-1] != '\n' || bytes.IndexByte(l[:len(l)-1], '\n') >= 0 {
			report("item %d is not exactly one newline terminated line: %q", i, outClip(l))
			continue
		}
		var v map[string]any
		if err := json.Unmarshal(l[:len(l)-1], &v); err != nil {
			report("item %d is not a complete JSON object (%v): %q", i, err, outClip(l))
			continue
		}
		id, _ := v["event_id"].(string)
		ev, ok := byID[id]
		switch {
		case !ok && allowUnknown && id != "":
		case !ok:
			report("item %d carries event_id %q that is not in the local log", i, id)
		case string(l) != ev.Line+"\n":
			report("item %d (event %s) differs from the log line at byte %d", i, id, outFirstDiff(string(l), ev.Line+"\n"))
		}
		count[id]++
	}
	return count
}

func outClip(b []byte) string {
	if len(b) > 120 {
		return string(b[:120]) + "..."
	}
	return string(b)
}

func outFirstDiff(a, b string) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// outMissing returns the event ids of want that are not in got.
func outMissing(want []Ev, got map[string]int) []string {
	var miss []string
	for _, e := range want {
		if got[e.str("event_id")] == 0 {
			miss = append(miss, e.str("event_id")+" "+e.Type())
		}
	}
	return miss
}

// outLogLines reads one log file strictly: it must be empty or end in a
// newline, and every line must be one complete JSON object.
func outLogLines(t *testing.T, path string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		return nil
	}
	if raw[len(raw)-1] != '\n' {
		t.Errorf("%s does not end with a newline (a torn last line)", filepath.Base(path))
	}
	var lines [][]byte
	for i, l := range bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n")) {
		var v map[string]any
		if err := json.Unmarshal(l, &v); err != nil {
			t.Errorf("%s line %d is not a complete JSON object: %v: %q", filepath.Base(path), i+1, err, outClip(l))
		}
		lines = append(lines, l)
	}
	return lines
}

// outPerm returns the permission bits of a file or directory.
func outPerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// outStopTimed stops the agent with SIGTERM and returns its exit code and how
// long it took.
func outStopTimed(a *agent) (int, time.Duration) {
	start := time.Now()
	code := a.Stop()
	return code, time.Since(start)
}

// outWaitAfterExit waits until the process with the pid has exited and an
// agent.health event follows its exit event in the log, so that every event of
// the process, and the counters after them, are in the log.
func outWaitAfterExit(t *testing.T, a *agent, pid int, timeout time.Duration) []Ev {
	t.Helper()
	return a.waitEvents(timeout, fmt.Sprintf("the exit of process %d and a health event after it", pid), func(evs []Ev) bool {
		exits := filterEv(ofType(evs, "process.exit"), func(e Ev) bool { return e.PID() == pid })
		if len(exits) == 0 {
			return false
		}
		for _, h := range ofType(evs, "agent.health") {
			if h.Seq() > exits[0].Seq() {
				return true
			}
		}
		return false
	})
}

// outWaitHealth polls the agent's log until cond holds for one of its health events.
func outWaitHealth(t *testing.T, a *agent, timeout time.Duration, what string, cond func(h Ev) bool) []Ev {
	t.Helper()
	var evs []Ev
	outWait(t, timeout, what, func() bool {
		evs = a.Events()
		for _, h := range ofType(evs, "agent.health") {
			if cond(h) {
				return true
			}
		}
		return false
	})
	return evs
}

// ----------------------------------------------------------------------------
// TCP receiver

// outConnPolicy tells the TCP receiver how to treat one connection.
type outConnPolicy struct {
	// Hang accepts the connection and does not read from it until
	// Release(index) is called or the receiver is closed.
	Hang bool
	// CloseAfterLines closes the connection (clean, FIN) after that many
	// complete lines.
	CloseAfterLines int
	// ResetAfterLines closes it abortively (RST) after that many lines.
	ResetAfterLines int
	// CutBytes with CutAfterLines: after CutAfterLines complete lines read
	// exactly CutBytes more bytes (which end inside the next line) and close.
	// Unread data makes the kernel answer with RST.
	CutAfterLines, CutBytes int
}

type outTCPOpts struct {
	Policy func(index int) outConnPolicy // nil: read everything
	TLS    *tls.Config                   // nil: plaintext
	RcvBuf int                           // SO_RCVBUF of the listener (accepted connections inherit it)
	Listen string                        // address to listen on; default 127.0.0.1:0
}

// outTCPConn is what the receiver saw on one connection.
type outTCPConn struct {
	Index        int
	Opened       time.Time
	Ended        time.Time // zero while the connection is open
	EndedBy      string    // "peer" or "server"
	Handshaken   bool      // TLS: the handshake completed
	HandshakeErr string
	Lines        [][]byte // complete lines with their newline
	Tail         []byte   // bytes after the last newline: an unterminated line
	Raw          []byte   // the first bytes as they came over the wire (ciphertext with TLS)
	Bytes        int      // bytes of application data read
}

// outRecvLine is one complete line in arrival order.
type outRecvLine struct {
	Conn int
	Line []byte
}

type outTCPServer struct {
	t    *testing.T
	ln   net.Listener
	Addr string
	opt  outTCPOpts

	mu      sync.Mutex
	conns   []*outTCPConn
	raw     []net.Conn
	order   []outRecvLine
	release map[int]chan struct{}
	stop    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

func outNewTCPServer(t *testing.T, o outTCPOpts) *outTCPServer {
	t.Helper()
	outEnsureLoopback(t)
	var lc net.ListenConfig
	if o.RcvBuf > 0 {
		lc.Control = func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, o.RcvBuf)
			}); err != nil {
				return err
			}
			return serr
		}
	}
	listen := o.Listen
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	ln, err := lc.Listen(context.Background(), "tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	s := &outTCPServer{t: t, ln: ln, Addr: ln.Addr().String(), opt: o, release: map[int]chan struct{}{}, stop: make(chan struct{})}
	s.wg.Add(1)
	go s.acceptLoop()
	t.Cleanup(s.Close)
	return s
}

func (s *outTCPServer) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		rec := &outTCPConn{Index: len(s.conns), Opened: time.Now()}
		s.conns = append(s.conns, rec)
		s.raw = append(s.raw, c)
		s.mu.Unlock()
		s.wg.Add(1)
		go s.serve(c, rec)
	}
}

func (s *outTCPServer) releaseCh(idx int) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.release[idx]
	if !ok {
		ch = make(chan struct{})
		s.release[idx] = ch
	}
	return ch
}

// Release lets a connection that was accepted with Hang start reading.
func (s *outTCPServer) Release(idx int) {
	ch := s.releaseCh(idx)
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func (s *outTCPServer) serve(c net.Conn, rec *outTCPConn) {
	defer s.wg.Done()
	closedByServer := false
	defer func() {
		s.mu.Lock()
		rec.Ended = time.Now()
		rec.EndedBy = "peer"
		if closedByServer {
			rec.EndedBy = "server"
		}
		s.mu.Unlock()
		c.Close()
	}()
	var pol outConnPolicy
	if s.opt.Policy != nil {
		pol = s.opt.Policy(rec.Index)
	}
	// Whatever the peer sends is also recorded as it came over the wire (the
	// ciphertext, with TLS), for the checks that nothing was sent in plaintext.
	wire := &outRecConn{Conn: c, add: func(b []byte) {
		s.mu.Lock()
		if room := 1<<20 - len(rec.Raw); room > 0 {
			rec.Raw = append(rec.Raw, b[:min(len(b), room)]...)
		}
		s.mu.Unlock()
	}}
	var rd net.Conn = wire
	if s.opt.TLS != nil {
		tc := tls.Server(wire, s.opt.TLS)
		_ = tc.SetDeadline(time.Now().Add(20 * time.Second))
		if err := tc.Handshake(); err != nil {
			s.mu.Lock()
			rec.HandshakeErr = err.Error()
			s.mu.Unlock()
			return
		}
		_ = tc.SetDeadline(time.Time{})
		s.mu.Lock()
		rec.Handshaken = true
		s.mu.Unlock()
		rd = tc
	}
	if pol.Hang {
		select {
		case <-s.releaseCh(rec.Index):
		case <-s.stop:
			return
		}
	}
	buf := make([]byte, 32<<10)
	lines := 0
	cutting, cutLeft := false, 0
	for {
		n, err := rd.Read(buf)
		data := buf[:n]
		s.mu.Lock()
		rec.Bytes += n
		action := ""
		for len(data) > 0 && action == "" {
			if cutting {
				take := min(len(data), cutLeft)
				rec.Tail = append(rec.Tail, data[:take]...)
				cutLeft -= take
				data = data[take:]
				if cutLeft == 0 {
					action = "close"
				}
				continue
			}
			i := bytes.IndexByte(data, '\n')
			if i < 0 {
				rec.Tail = append(rec.Tail, data...)
				break
			}
			line := append(append([]byte(nil), rec.Tail...), data[:i+1]...)
			rec.Tail = nil
			data = data[i+1:]
			rec.Lines = append(rec.Lines, line)
			s.order = append(s.order, outRecvLine{Conn: rec.Index, Line: line})
			lines++
			switch {
			case pol.CloseAfterLines > 0 && lines >= pol.CloseAfterLines:
				action = "close"
			case pol.ResetAfterLines > 0 && lines >= pol.ResetAfterLines:
				action = "reset"
			case pol.CutBytes > 0 && lines >= pol.CutAfterLines:
				cutting, cutLeft = true, pol.CutBytes
			}
		}
		s.mu.Unlock()
		switch action {
		case "close":
			closedByServer = true
			return
		case "reset":
			closedByServer = true
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			return
		}
		if err != nil {
			return
		}
	}
}

// outRecConn passes everything that is read through add.
type outRecConn struct {
	net.Conn
	add func([]byte)
}

func (c *outRecConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.add(p[:n])
	}
	return n, err
}

// Conns returns snapshots of all connections accepted so far.
func (s *outTCPServer) Conns() []outTCPConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]outTCPConn, len(s.conns))
	for i, c := range s.conns {
		out[i] = *c
		out[i].Lines = append([][]byte(nil), c.Lines...)
		out[i].Tail = append([]byte(nil), c.Tail...)
		out[i].Raw = append([]byte(nil), c.Raw...)
	}
	return out
}

func (s *outTCPServer) NumConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// Lines returns every complete line received, in arrival order.
func (s *outTCPServer) Lines() []outRecvLine {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]outRecvLine(nil), s.order...)
}

// LineBytes is Lines without the connection numbers.
func (s *outTCPServer) LineBytes() [][]byte {
	var out [][]byte
	for _, l := range s.Lines() {
		out = append(out, l.Line)
	}
	return out
}

// AllEnded reports whether every connection accepted so far has ended.
func (s *outTCPServer) AllEnded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		if c.Ended.IsZero() {
			return false
		}
	}
	return true
}

func (s *outTCPServer) Close() {
	s.once.Do(func() {
		close(s.stop)
		s.ln.Close()
		s.mu.Lock()
		for _, c := range s.raw {
			c.Close()
		}
		s.mu.Unlock()
	})
	s.wg.Wait()
}

// ----------------------------------------------------------------------------
// UDP receiver

type outUDPServer struct {
	conn *net.UDPConn
	Addr string

	mu     sync.Mutex
	dgrams [][]byte
	wg     sync.WaitGroup
}

func outNewUDPServer(t *testing.T) *outUDPServer {
	t.Helper()
	return outNewUDPServerAt(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

// outNewUDPServerAt listens on the given address (port 0: an ephemeral port).
func outNewUDPServerAt(t *testing.T, addr *net.UDPAddr) *outUDPServer {
	t.Helper()
	outEnsureLoopback(t)
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	// A large receive buffer, so that the receiver does not lose datagrams
	// that the kernel delivered while it was not scheduled (the privileged
	// force variant ignores net.core.rmem_max).
	if raw, err := conn.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 64<<20) != nil {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 64<<20)
			}
		})
	}
	u := &outUDPServer{conn: conn, Addr: conn.LocalAddr().String()}
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		buf := make([]byte, 70000)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			u.mu.Lock()
			u.dgrams = append(u.dgrams, append([]byte(nil), buf[:n]...))
			u.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		conn.Close()
		u.wg.Wait()
	})
	return u
}

func (u *outUDPServer) Datagrams() [][]byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([][]byte(nil), u.dgrams...)
}

func (u *outUDPServer) Count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.dgrams)
}

// ----------------------------------------------------------------------------
// Webhook receiver

// outHookStep scripts the answer to one request.
type outHookStep struct {
	Status int               // 0: 200
	Header map[string]string // extra response headers
	Delay  time.Duration     // pause before answering
	Hang   bool              // never answer; wait until the client gives up
	// RetryAfterDate sets Retry-After to the HTTP date this far in the future.
	RetryAfterDate time.Duration
	// StallBody sends the status and 64 KiB of the body, then never ends the body.
	StallBody bool
}

// outHookReq is one request as the receiver saw it.
type outHookReq struct {
	N        int // arrival number, from 1
	At       time.Time
	Method   string
	Path     string
	RawQuery string
	Header   http.Header
	Body     []byte
	Length   int64    // Content-Length (-1: not known, chunked)
	Encoding []string // Transfer-Encoding
	Step     outHookStep
	Done     bool // the answer was sent
	Status   int  // the status that was sent
}

type outHookServer struct {
	URL string
	srv *httptest.Server

	mu     sync.Mutex
	reqs   []*outHookReq
	script []outHookStep
	def    outHookStep
	stop   chan struct{}
	once   sync.Once
}

// outNewHookServer starts an HTTP receiver. The first requests are answered as
// scripted, every later one with 200 (or def, if set via SetDefault).
func outNewHookServer(t *testing.T, script ...outHookStep) *outHookServer {
	t.Helper()
	return outStartHook(t, false, nil, "", script)
}

// outNewHookServerAt listens on the given address, for example [::1]:0.
func outNewHookServerAt(t *testing.T, listen string, script ...outHookStep) *outHookServer {
	t.Helper()
	return outStartHook(t, false, nil, listen, script)
}

// outNewHookServerTLS is the same over HTTPS. With a nil certificate the
// server presents the self-signed certificate of net/http/httptest, which no
// system trust store contains.
func outNewHookServerTLS(t *testing.T, cert *tls.Certificate, script ...outHookStep) *outHookServer {
	t.Helper()
	return outStartHook(t, true, cert, "", script)
}

func outStartHook(t *testing.T, useTLS bool, cert *tls.Certificate, listen string, script []outHookStep) *outHookServer {
	t.Helper()
	outEnsureLoopback(t)
	h := &outHookServer{script: script, stop: make(chan struct{})}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(h.handle))
	if listen != "" {
		l, err := net.Listen("tcp", listen)
		if err != nil {
			t.Fatal(err)
		}
		srv.Listener.Close()
		srv.Listener = l
	}
	if useTLS {
		srv.Config.ErrorLog = log.New(io.Discard, "", 0) // failed handshakes are expected
		if cert != nil {
			srv.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
		}
		srv.StartTLS()
	} else {
		srv.Start()
	}
	h.srv, h.URL = srv, srv.URL
	t.Cleanup(h.Close)
	return h
}

// SetDefault sets the answer to every request after the script.
func (h *outHookServer) SetDefault(s outHookStep) {
	h.mu.Lock()
	h.def = s
	h.mu.Unlock()
}

func (h *outHookServer) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	h.mu.Lock()
	req := &outHookReq{
		N: len(h.reqs) + 1, At: time.Now(), Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery,
		Header: r.Header.Clone(), Body: body, Length: r.ContentLength, Encoding: r.TransferEncoding,
	}
	step := h.def
	if len(h.script) > 0 {
		step, h.script = h.script[0], h.script[1:]
	}
	req.Step = step
	h.reqs = append(h.reqs, req)
	h.mu.Unlock()

	if step.Hang {
		select {
		case <-r.Context().Done():
		case <-h.stop:
		}
		return
	}
	if step.Delay > 0 {
		select {
		case <-time.After(step.Delay):
		case <-r.Context().Done():
			return
		case <-h.stop:
			return
		}
	}
	for k, v := range step.Header {
		w.Header().Set(k, v)
	}
	if step.RetryAfterDate > 0 {
		w.Header().Set("Retry-After", time.Now().Add(step.RetryAfterDate).UTC().Format(http.TimeFormat))
	}
	status := step.Status
	if status == 0 {
		status = 200
	}
	w.WriteHeader(status)
	h.mu.Lock()
	req.Done, req.Status = true, status
	h.mu.Unlock()
	if step.StallBody {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 64<<10)) // more than the agent reads of an answer
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-r.Context().Done():
		case <-h.stop:
		}
	}
}

// Requests returns copies of all requests received so far.
func (h *outHookServer) Requests() []outHookReq {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]outHookReq, len(h.reqs))
	for i, r := range h.reqs {
		out[i] = *r
	}
	return out
}

func (h *outHookServer) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.reqs)
}

// Accepted returns the bodies of the requests that were answered with 2xx.
func (h *outHookServer) Accepted() []outHookReq {
	var out []outHookReq
	for _, r := range h.Requests() {
		if r.Done && r.Status >= 200 && r.Status < 300 {
			out = append(out, r)
		}
	}
	return out
}

func (h *outHookServer) Close() {
	h.once.Do(func() {
		close(h.stop)
		h.srv.CloseClientConnections()
		h.srv.Close()
	})
}

// ----------------------------------------------------------------------------
// PKI

type outCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func outNewCA(t *testing.T, name string) *outCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-72 * time.Hour),
		NotAfter:              time.Now().Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &outCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// writePEM stores the CA certificate in dir and returns the path.
func (ca *outCA) writePEM(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// issue creates a server certificate for the given names and addresses that
// is valid between notBefore and notAfter.
func (ca *outCA) issue(t *testing.T, dns []string, ips []net.IP, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "collector"},
		DNSNames:     dns,
		IPAddresses:  ips,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// outValidity is a validity window around now.
func outValidity() (time.Time, time.Time) {
	return time.Now().Add(-time.Hour), time.Now().Add(48 * time.Hour)
}
