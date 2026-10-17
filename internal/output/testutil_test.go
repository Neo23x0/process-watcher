package output

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const testWait = 10 * time.Second

// holdLogEnv makes the test binary act as a helper process that opens the
// named log file, reports "ready" and keeps the writer lock until its stdin
// is closed (see TestFileLockAcrossProcesses).
const holdLogEnv = "OUTPUT_TEST_HOLD_LOG"

func holdLogFile(path string) {
	f, err := OpenFile(FileOptions{Path: path, SyncInterval: time.Hour})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(3)
	}
	fmt.Println("ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
	_ = f.Close()
	os.Exit(0)
}

func TestMain(m *testing.M) {
	if path := os.Getenv(holdLogEnv); path != "" {
		holdLogFile(path)
		return
	}
	code := m.Run()
	if code == 0 {
		if leaks := waitNoLeaks(5 * time.Second); len(leaks) > 0 {
			fmt.Fprintf(os.Stderr, "goroutines leaked by package output:\n%s\n", strings.Join(leaks, "\n\n"))
			code = 1
		}
	}
	os.Exit(code)
}

// --- goroutine leak detection ----------------------------------------------

// leakedGoroutines returns the stacks of goroutines that were started by this
// package's production code (not by test helpers), plus leftover client side
// HTTP connection goroutines.
func leakedGoroutines() []string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	const pkg = "github.com/Neo23x0/process-watcher/internal/output."
	var leaks []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "net/http.(*persistConn)") {
			leaks = append(leaks, g)
			continue
		}
		i := strings.LastIndex(g, "created by ")
		if i < 0 {
			continue
		}
		creator := strings.SplitN(g[i:], "\n", 3)
		if !strings.Contains(creator[0], pkg) {
			continue
		}
		if len(creator) > 1 && strings.Contains(creator[1], "_test.go") {
			continue // started by a test helper
		}
		leaks = append(leaks, g)
	}
	return leaks
}

func waitNoLeaks(d time.Duration) []string {
	deadline := time.Now().Add(d)
	for {
		leaks := leakedGoroutines()
		if len(leaks) == 0 || time.Now().After(deadline) {
			return leaks
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// assertNoLeaks fails the test if production goroutines outlive the outputs.
func assertNoLeaks(t *testing.T) {
	t.Helper()
	if leaks := waitNoLeaks(5 * time.Second); len(leaks) > 0 {
		t.Fatalf("leaked goroutines:\n%s", strings.Join(leaks, "\n\n"))
	}
}

// --- polling and logging -----------------------------------------------------

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout after %s waiting for %s", testWait, what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLogger() (*slog.Logger, *syncBuffer) {
	buf := &syncBuffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

// makeLine builds a JSONL line with the given event id and about size bytes.
func makeLine(id string, size int) []byte {
	head := fmt.Sprintf(`{"schema_version":1,"event_id":%q,"pad":"`, id)
	tail := "\"}\n"
	pad := size - len(head) - len(tail)
	if pad < 0 {
		pad = 0
	}
	return []byte(head + strings.Repeat("x", pad) + tail)
}

// --- fakes --------------------------------------------------------------------

// fakeConn is a net.Conn whose Write behaviour the test controls. Read blocks
// until the connection is closed, like an idle real connection.
type fakeConn struct {
	mu      sync.Mutex
	data    []byte
	writes  int
	writeFn func(c *fakeConn, p []byte) (int, error)

	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeConn() *fakeConn { return &fakeConn{closed: make(chan struct{})} }

// record appends p to what the "peer" received.
func (c *fakeConn) record(p []byte) {
	c.mu.Lock()
	c.data = append(c.data, p...)
	c.mu.Unlock()
}

func (c *fakeConn) received() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.data...)
}

func (c *fakeConn) writeCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

func (c *fakeConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *fakeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	fn := c.writeFn
	c.mu.Unlock()
	if fn != nil {
		return fn(c, p)
	}
	if c.isClosed() {
		return 0, net.ErrClosed
	}
	c.record(p)
	return len(p), nil
}

func (c *fakeConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *fakeConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeConn) LocalAddr() net.Addr              { return fakeAddr("local") }
func (c *fakeConn) RemoteAddr() net.Addr             { return fakeAddr("remote") }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

// blockUntilClosed is a writeFn that hangs like a stalled peer until the
// connection is closed; started is closed on the first call.
func blockUntilClosed(started chan struct{}) func(*fakeConn, []byte) (int, error) {
	var once sync.Once
	return func(c *fakeConn, _ []byte) (int, error) {
		once.Do(func() { close(started) })
		<-c.closed
		return 0, net.ErrClosed
	}
}

type sleepRecorder struct {
	mu    sync.Mutex
	waits []time.Duration
}

// Sleep records the requested wait and returns at once.
func (s *sleepRecorder) Sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.waits = append(s.waits, d)
	s.mu.Unlock()
	return ctx.Err()
}

func (s *sleepRecorder) all() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.waits...)
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fastHooks make retries run in milliseconds without jitter.
func fastHooks() Hooks {
	return Hooks{BackoffBase: time.Millisecond, BackoffMax: 4 * time.Millisecond, BackoffJitter: -1}
}

// --- TCP and UDP sinks ----------------------------------------------------------

// sinkConn records everything one accepted connection received.
type sinkConn struct {
	mu  sync.Mutex
	buf []byte
}

func (sc *sinkConn) append(p []byte) {
	sc.mu.Lock()
	sc.buf = append(sc.buf, p...)
	sc.mu.Unlock()
}

func (sc *sinkConn) bytes() []byte {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return append([]byte(nil), sc.buf...)
}

// tcpSink is a local TCP (optionally TLS) receiver that records what each
// connection sends. A handler can replace the default read-everything
// behaviour to simulate misbehaving receivers.
type tcpSink struct {
	ln      net.Listener
	handler func(idx int, c net.Conn, sc *sinkConn)

	wg    sync.WaitGroup
	mu    sync.Mutex
	conns []*sinkConn
	raw   []net.Conn
}

func newTCPSink(t *testing.T, tlsCfg *tls.Config, handler func(idx int, c net.Conn, sc *sinkConn)) *tcpSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	s := &tcpSink{ln: ln, handler: handler}
	s.wg.Add(1)
	go s.acceptLoop()
	t.Cleanup(s.Close)
	return s
}

func (s *tcpSink) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		sc := &sinkConn{}
		s.mu.Lock()
		idx := len(s.conns)
		s.conns = append(s.conns, sc)
		s.raw = append(s.raw, c)
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			if s.handler != nil {
				s.handler(idx, c, sc)
				return
			}
			readAllInto(c, sc)
		}()
	}
}

func readAllInto(c net.Conn, sc *sinkConn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			sc.append(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func (s *tcpSink) Addr() string { return s.ln.Addr().String() }

func (s *tcpSink) ConnCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// Data returns what connection idx received (nil if there is no such connection).
func (s *tcpSink) Data(idx int) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idx >= len(s.conns) {
		return nil
	}
	return s.conns[idx].bytes()
}

// All returns the bytes of all connections concatenated in connection order.
func (s *tcpSink) All() []byte {
	s.mu.Lock()
	conns := append([]*sinkConn(nil), s.conns...)
	s.mu.Unlock()
	var all []byte
	for _, sc := range conns {
		all = append(all, sc.bytes()...)
	}
	return all
}

func (s *tcpSink) waitBytes(t *testing.T, n int) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%d bytes at the TCP sink", n), func() bool { return len(s.All()) >= n })
}

func (s *tcpSink) Close() {
	_ = s.ln.Close()
	s.mu.Lock()
	for _, c := range s.raw {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

type udpSink struct {
	pc   *net.UDPConn
	wg   sync.WaitGroup
	mu   sync.Mutex
	pkts [][]byte
}

func newUDPSink(t *testing.T) *udpSink {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	_ = pc.SetReadBuffer(4 << 20)
	s := &udpSink{pc: pc}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		buf := make([]byte, 70000)
		for {
			n, _, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			s.mu.Lock()
			s.pkts = append(s.pkts, append([]byte(nil), buf[:n]...))
			s.mu.Unlock()
		}
	}()
	t.Cleanup(func() { _ = pc.Close(); s.wg.Wait() })
	return s
}

func (s *udpSink) Addr() string { return s.pc.LocalAddr().String() }

func (s *udpSink) Packets() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.pkts...)
}

func (s *udpSink) waitPackets(t *testing.T, n int) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%d datagrams at the UDP sink", n), func() bool { return len(s.Packets()) >= n })
}

// --- webhook server -----------------------------------------------------------------

type recordedRequest struct {
	Method string
	Header http.Header
	Body   []byte
	URI    string
}

// hookServer records every request before handing it to the test's handler.
type hookServer struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []recordedRequest
}

// newHookServer starts an HTTP (or HTTPS) server. handle gets the 1-based
// number of the request; a nil handle answers 200.
func newHookServer(t *testing.T, useTLS bool, handle func(w http.ResponseWriter, r *http.Request, n int)) *hookServer {
	t.Helper()
	hs := &hookServer{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hs.mu.Lock()
		hs.reqs = append(hs.reqs, recordedRequest{Method: r.Method, Header: r.Header.Clone(), Body: body, URI: r.RequestURI})
		n := len(hs.reqs)
		hs.mu.Unlock()
		if handle != nil {
			handle(w, r, n)
		}
	})
	hs.Server = httptest.NewUnstartedServer(h)
	hs.Server.Config.ErrorLog = log.New(io.Discard, "", 0) // failed TLS handshakes are expected in tests
	if useTLS {
		hs.Server.StartTLS()
	} else {
		hs.Server.Start()
	}
	t.Cleanup(hs.Server.Close)
	return hs
}

func (hs *hookServer) Requests() []recordedRequest {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	return append([]recordedRequest(nil), hs.reqs...)
}

func (hs *hookServer) Count() int {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	return len(hs.reqs)
}

// --- test PKI --------------------------------------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
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
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// writePEM stores the CA certificate in a temp file and returns its path.
func (ca *testCA) writePEM(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// issue creates a server certificate valid between notBefore and notAfter.
func (ca *testCA) issue(t *testing.T, dns []string, ips []net.IP, notBefore, notAfter time.Time) tls.Certificate {
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

// validNow is a validity window around the current time.
func validNow() (time.Time, time.Time) {
	return time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
}

// shutdownRemote shuts a remote down within a generous deadline and fails the
// test if events were dropped unexpectedly.
func shutdownRemote(t *testing.T, r Remote) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	if dropped := r.Shutdown(ctx); dropped != 0 {
		t.Errorf("%s: Shutdown dropped %d events, want 0", r.Name(), dropped)
	}
}

// cleanupShutdown shuts r down when the test ends, ignoring dropped events.
func cleanupShutdown(t *testing.T, r Remote) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		r.Shutdown(ctx)
	})
}
