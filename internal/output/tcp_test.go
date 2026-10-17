package output

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fast gives the hooks millisecond backoff without jitter unless set.
func fast(h Hooks) Hooks {
	if h.BackoffBase == 0 {
		h.BackoffBase = time.Millisecond
	}
	if h.BackoffMax == 0 {
		h.BackoffMax = 4 * time.Millisecond
	}
	if h.BackoffJitter == 0 {
		h.BackoffJitter = -1
	}
	return h
}

func newTCP(t *testing.T, opts TCPOptions) *tcpRemote {
	t.Helper()
	opts.Hooks = fast(opts.Hooks)
	r, err := NewTCP(opts)
	if err != nil {
		t.Fatalf("NewTCP: %v", err)
	}
	cleanupShutdown(t, r)
	return r.(*tcpRemote)
}

func TestTCPDeliversInOrderOverOneConnection(t *testing.T) {
	sink := newTCPSink(t, nil, nil)
	r := newTCP(t, TCPOptions{Address: sink.Addr(), QueueSize: 1000})

	var want []byte
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("evt-%04d", i)
		line := makeLine(id, 80+i*7)
		want = append(want, line...)
		if !r.Enqueue(id, line) {
			t.Fatalf("event %d rejected", i)
		}
	}
	sink.waitBytes(t, len(want))
	if got := sink.All(); !bytes.Equal(got, want) {
		t.Fatal("received stream differs from the enqueued lines")
	}
	// The receiver can see the last line a moment before the sender counts it.
	waitFor(t, "HandedOver", func() bool { return r.Stats().HandedOver == 200 })
	st := r.Stats()
	if st.Failed != 0 || st.Retries != 0 || st.DroppedQueueFull != 0 {
		t.Errorf("stats = %+v", st)
	}
	if n := sink.ConnCount(); n != 1 {
		t.Errorf("connections = %d, want one persistent connection", n)
	}
	if r.Name() != "tcp" {
		t.Errorf("Name = %q", r.Name())
	}
	shutdownRemote(t, r)
}

// The receiver resets the connection while a large line is in flight. The
// whole line must arrive again, byte-identical, on a new connection.
func TestTCPRetriesWholeLineAfterConnectionResetMidLine(t *testing.T) {
	const eventID = "evt-big"
	line := makeLine(eventID, 24<<20)
	sink := newTCPSink(t, nil, func(idx int, c net.Conn, sc *sinkConn) {
		if idx == 0 {
			buf := make([]byte, 64<<10)
			n, _ := io.ReadFull(c, buf)
			sc.append(buf[:n])
			_ = c.(*net.TCPConn).SetLinger(0) // RST instead of FIN
			return
		}
		readAllInto(c, sc)
	})
	r := newTCP(t, TCPOptions{Address: sink.Addr(), MaxRetries: 3, WriteTimeout: 60 * time.Second})
	if !r.Enqueue(eventID, line) {
		t.Fatal("rejected")
	}
	waitFor(t, "the complete line on the second connection", func() bool { return len(sink.Data(1)) >= len(line) })
	waitFor(t, "HandedOver", func() bool { return r.Stats().HandedOver == 1 })

	if !bytes.Equal(sink.Data(1), line) {
		t.Fatal("the retried line is not byte-identical")
	}
	if first := sink.Data(0); len(first) == 0 || len(first) >= len(line) || !bytes.HasPrefix(line, first) {
		t.Fatalf("first connection received %d bytes, want a proper prefix of the line", len(first))
	}
	if !bytes.Contains(sink.Data(1), []byte(`"event_id":"`+eventID+`"`)) {
		t.Error("event id missing from the retried line")
	}
	st := r.Stats()
	if st.Retries != 1 || st.Failed != 0 {
		t.Errorf("stats = %+v, want exactly one retry and no failure", st)
	}
}

func TestTCPRetryAfterPartialWriteOnFakeConn(t *testing.T) {
	line := makeLine("evt-1", 200)
	c1, c2 := newFakeConn(), newFakeConn()
	c1.writeFn = func(c *fakeConn, p []byte) (int, error) {
		c.record(p[:10]) // ten bytes reach the peer, then the connection breaks
		return 10, errors.New("connection reset by peer (injected)")
	}
	var mu sync.Mutex
	var dialed []string
	conns := []*fakeConn{c1, c2}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		dialed = append(dialed, network+" "+address)
		if len(dialed) > len(conns) {
			return nil, errors.New("unexpected dial")
		}
		return conns[len(dialed)-1], nil
	}
	r := newTCP(t, TCPOptions{Address: "collector.example.test:9000", MaxRetries: 2, Hooks: Hooks{Dial: dial}})
	r.Enqueue("evt-1", line)
	waitFor(t, "HandedOver", func() bool { return r.Stats().HandedOver == 1 })

	if got := c1.received(); !bytes.Equal(got, line[:10]) {
		t.Errorf("first connection received %q", got)
	}
	if got := c2.received(); !bytes.Equal(got, line) {
		t.Errorf("second connection received %d bytes, want the full identical line", len(got))
	}
	if !c1.isClosed() {
		t.Error("the broken connection was not closed")
	}
	mu.Lock()
	defer mu.Unlock()
	// The dialer gets the host name every time; it resolves it anew.
	want := []string{"tcp collector.example.test:9000", "tcp collector.example.test:9000"}
	if fmt.Sprint(dialed) != fmt.Sprint(want) {
		t.Errorf("dials = %v, want %v", dialed, want)
	}
	if st := r.Stats(); st.Retries != 1 || st.Failed != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestTCPCompletesShortWrites(t *testing.T) {
	c := newFakeConn()
	c.writeFn = func(c *fakeConn, p []byte) (int, error) {
		n := min(7, len(p))
		c.record(p[:n])
		return n, nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) { return c, nil }
	r := newTCP(t, TCPOptions{Address: "collector.example.test:9000", Hooks: Hooks{Dial: dial}})
	line := makeLine("evt-short", 100)
	r.Enqueue("evt-short", line)
	waitFor(t, "HandedOver", func() bool { return r.Stats().HandedOver == 1 })
	if !bytes.Equal(c.received(), line) {
		t.Error("line differs after short writes")
	}
	if n := c.writeCalls(); n < 15 {
		t.Errorf("write calls = %d, want at least 15 for 100 bytes at 7 per call", n)
	}
}

// A receiver that closes an idle connection (restart) must not cost the next
// event: the closed connection is noticed and replaced before writing.
func TestTCPReplacesConnectionClosedByPeer(t *testing.T) {
	sink := newTCPSink(t, nil, func(idx int, c net.Conn, sc *sinkConn) {
		line, _ := bufio.NewReader(c).ReadBytes('\n')
		sc.append(line) // then the handler returns and the connection is closed
	})
	r := newTCP(t, TCPOptions{Address: sink.Addr(), MaxRetries: 2})

	l1, l2 := makeLine("e1", 120), makeLine("e2", 130)
	r.Enqueue("e1", l1)
	waitFor(t, "first event", func() bool { return r.Stats().HandedOver == 1 })
	waitFor(t, "the close to be noticed", r.peerClosed)

	r.Enqueue("e2", l2)
	waitFor(t, "second event", func() bool { return r.Stats().HandedOver == 2 })
	waitFor(t, "second event at the sink", func() bool { return len(sink.Data(1)) == len(l2) })

	if !bytes.Equal(sink.Data(0), l1) || !bytes.Equal(sink.Data(1), l2) {
		t.Error("events not delivered exactly once on their own connection")
	}
	if st := r.Stats(); st.Retries != 0 || st.Failed != 0 {
		t.Errorf("stats = %+v, want no retries and no failures", st)
	}
}

func TestTCPGivesUpAfterMaxRetriesAndContinues(t *testing.T) {
	var dials atomic.Int32
	dial := func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("connection refused (injected)")
	}
	sleeps := &sleepRecorder{}
	r := newTCP(t, TCPOptions{Address: "collector.example.test:9000", MaxRetries: 3,
		Hooks: Hooks{Dial: dial, Sleep: sleeps.Sleep}})
	r.Enqueue("e1", makeLine("e1", 100))
	r.Enqueue("e2", makeLine("e2", 100))
	waitFor(t, "both events to be given up", func() bool { return r.Stats().Failed == 2 })

	if n := dials.Load(); n != 8 {
		t.Errorf("dial attempts = %d, want 2 events x (3 retries + 1) = 8", n)
	}
	st := r.Stats()
	if st.Retries != 6 || st.HandedOver != 0 {
		t.Errorf("stats = %+v", st)
	}
	for _, want := range []string{"event dropped after 4 attempts", "collector.example.test:9000", "connection refused"} {
		if !strings.Contains(st.LastError, want) {
			t.Errorf("LastError %q lacks %q", st.LastError, want)
		}
	}
	ms := time.Millisecond
	if got, want := fmt.Sprint(sleeps.all()), fmt.Sprint([]time.Duration{ms, 2 * ms, 4 * ms, ms, 2 * ms, 4 * ms}); got != want {
		t.Errorf("backoff waits = %s, want %s (doubling, capped, restarting per event)", got, want)
	}
}

// With production defaults the waits are 1s, 2s, 4s, 8s, 16s and then 30s.
func TestTCPDefaultBackoffSchedule(t *testing.T) {
	sleeps := &sleepRecorder{}
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("down") }
	r, err := NewTCP(TCPOptions{Address: "collector.example.test:9000", MaxRetries: 6,
		Hooks: Hooks{Dial: dial, Sleep: sleeps.Sleep, BackoffJitter: -1}})
	must(t, err)
	cleanupShutdown(t, r)
	r.Enqueue("e1", makeLine("e1", 100))
	waitFor(t, "event to be given up", func() bool { return r.Stats().Failed == 1 })
	var want []time.Duration
	for _, s := range []int{1, 2, 4, 8, 16, 30} {
		want = append(want, time.Duration(s)*time.Second)
	}
	if got := sleeps.all(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("waits = %v, want %v", got, want)
	}
}

func TestTCPNoRetriesWhenMaxRetriesIsZero(t *testing.T) {
	var dials atomic.Int32
	dial := func(context.Context, string, string) (net.Conn, error) { dials.Add(1); return nil, errors.New("down") }
	r := newTCP(t, TCPOptions{Address: "collector.example.test:9000", Hooks: Hooks{Dial: dial}})
	r.Enqueue("e1", makeLine("e1", 100))
	waitFor(t, "failure", func() bool { return r.Stats().Failed == 1 })
	if dials.Load() != 1 || r.Stats().Retries != 0 {
		t.Errorf("dials = %d, retries = %d, want a single attempt", dials.Load(), r.Stats().Retries)
	}
}

func TestTCPTLS(t *testing.T) {
	good := newTestCA(t, "good CA")
	other := newTestCA(t, "other CA")
	nb, na := validNow()
	loopback := []net.IP{net.IPv4(127, 0, 0, 1)}

	tests := []struct {
		name       string
		cert       func() tls.Certificate
		trust      *testCA
		serverName string
		wantOK     bool
	}{
		{"server_name override matches the DNS name", func() tls.Certificate { return good.issue(t, []string{"collector.test"}, nil, nb, na) }, good, "collector.test", true},
		{"IP address matches the IP SAN without override", func() tls.Certificate { return good.issue(t, nil, loopback, nb, na) }, good, "", true},
		{"hostname mismatch without override", func() tls.Certificate { return good.issue(t, []string{"collector.test"}, nil, nb, na) }, good, "", false},
		{"wrong server_name override", func() tls.Certificate { return good.issue(t, []string{"collector.test"}, nil, nb, na) }, good, "other.test", false},
		{"certificate from an unknown CA", func() tls.Certificate { return good.issue(t, []string{"collector.test"}, nil, nb, na) }, other, "collector.test", false},
		{"expired certificate", func() tls.Certificate {
			return good.issue(t, []string{"collector.test"}, nil, nb.Add(-48*time.Hour), nb.Add(-24*time.Hour))
		}, good, "collector.test", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sink := newTCPSink(t, &tls.Config{Certificates: []tls.Certificate{tc.cert()}}, nil)
			r := newTCP(t, TCPOptions{
				Address: sink.Addr(), TLS: true, CAFile: tc.trust.writePEM(t), ServerName: tc.serverName,
				MaxRetries: 1, ConnectTimeout: 5 * time.Second,
			})
			line := makeLine("evt-tls", 300)
			r.Enqueue("evt-tls", line)

			if tc.wantOK {
				sink.waitBytes(t, len(line))
				if !bytes.Equal(sink.All(), line) {
					t.Fatal("payload differs")
				}
				waitFor(t, "HandedOver", func() bool { return r.Stats().HandedOver == 1 })
				return
			}
			waitFor(t, "the event to be given up", func() bool { return r.Stats().Failed == 1 })
			st := r.Stats()
			if st.HandedOver != 0 || st.Retries != 1 {
				t.Errorf("stats = %+v", st)
			}
			if !strings.Contains(st.LastError, "TLS handshake") || !strings.Contains(st.LastError, "certificate") {
				t.Errorf("LastError = %q, want a TLS certificate verification error", st.LastError)
			}
			t.Logf("LastError: %s", st.LastError)
			if got := sink.All(); len(got) != 0 {
				t.Errorf("%d bytes of application data reached a receiver that failed verification", len(got))
			}
		})
	}
}

// A TLS client talking to a receiver without TLS must give up, never send the
// payload in the clear.
func TestTCPTLSNeverFallsBackToPlaintext(t *testing.T) {
	sink := newTCPSink(t, nil, nil)
	ca := newTestCA(t, "ca")
	r := newTCP(t, TCPOptions{Address: sink.Addr(), TLS: true, CAFile: ca.writePEM(t), ServerName: "collector.test",
		MaxRetries: 1, ConnectTimeout: 100 * time.Millisecond})
	r.Enqueue("secret-evt", makeLine("secret-evt", 300))
	waitFor(t, "the event to be given up", func() bool { return r.Stats().Failed == 1 })

	data := sink.All()
	if bytes.Contains(data, []byte("secret-evt")) || bytes.Contains(data, []byte("schema_version")) {
		t.Fatal("event payload was sent in plaintext")
	}
	if len(data) == 0 || data[0] != 0x16 {
		t.Errorf("expected a TLS ClientHello at the plaintext receiver, got % x", data[:min(len(data), 8)])
	}
}

// crypto/tls would spend up to 5s on close_notify when closing a session whose
// peer has stopped reading. A write timeout must drop the connection at once.
func TestTCPStalledTLSPeerIsDroppedPromptly(t *testing.T) {
	ca := newTestCA(t, "ca")
	nb, na := validNow()
	cert := ca.issue(t, []string{"collector.test"}, nil, nb, na)
	release := make(chan struct{})
	sink := newTCPSink(t, &tls.Config{Certificates: []tls.Certificate{cert}}, func(idx int, c net.Conn, sc *sinkConn) {
		_ = c.(*tls.Conn).Handshake()
		<-release // then never read application data
	})
	t.Cleanup(func() { close(release) })
	r := newTCP(t, TCPOptions{Address: sink.Addr(), TLS: true, CAFile: ca.writePEM(t), ServerName: "collector.test",
		WriteTimeout: 100 * time.Millisecond})

	start := time.Now()
	r.Enqueue("big", makeLine("big", 32<<20)) // far beyond the socket buffers
	waitFor(t, "the write to time out", func() bool { return r.Stats().Failed == 1 })
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("giving up took %s; the connection was not dropped promptly", d)
	}
	if st := r.Stats(); !strings.Contains(st.LastError, "timeout") {
		t.Errorf("LastError = %q, want a timeout", st.LastError)
	}
	start = time.Now()
	shutdownRemote(t, r)
	if d := time.Since(start); d > time.Second {
		t.Errorf("Shutdown took %s", d)
	}
}

// At the end of a healthy run the TLS session is closed politely, and the
// receiver sees the end of the stream after every line.
func TestTCPTLSShutdownEndsTheStreamCleanly(t *testing.T) {
	ca := newTestCA(t, "ca")
	nb, na := validNow()
	cert := ca.issue(t, []string{"collector.test"}, nil, nb, na)
	ended := make(chan error, 1)
	sink := newTCPSink(t, &tls.Config{Certificates: []tls.Certificate{cert}}, func(idx int, c net.Conn, sc *sinkConn) {
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			sc.append(buf[:n])
			if err != nil {
				ended <- err
				return
			}
		}
	})
	r := newTCP(t, TCPOptions{Address: sink.Addr(), TLS: true, CAFile: ca.writePEM(t), ServerName: "collector.test"})
	line := makeLine("evt", 200)
	r.Enqueue("evt", line)
	shutdownRemote(t, r)
	select {
	case err := <-ended:
		if err != io.EOF {
			t.Errorf("receiver saw %v at the end of the stream, want a clean EOF", err)
		}
	case <-time.After(testWait):
		t.Fatal("the connection was not closed by Shutdown")
	}
	if !bytes.Equal(sink.All(), line) {
		t.Error("line not delivered before the close")
	}
}

func TestTCPTLSConfig(t *testing.T) {
	ca := newTestCA(t, "ca")
	caFile := ca.writePEM(t)
	tests := []struct {
		name         string
		opts         TCPOptions
		wantName     string
		wantCustomCA bool
	}{
		{"system roots, host from address", TCPOptions{Address: "collector.example.net:9000", TLS: true}, "collector.example.net", false},
		{"IPv6 literal", TCPOptions{Address: "[2001:db8::10]:9000", TLS: true}, "2001:db8::10", false},
		{"server name override", TCPOptions{Address: "192.0.2.10:9000", TLS: true, ServerName: "collector.test"}, "collector.test", false},
		{"CA file", TCPOptions{Address: "192.0.2.10:9000", TLS: true, CAFile: caFile}, "192.0.2.10", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newTCP(t, tc.opts)
			cfg := r.tlsConf
			if cfg == nil {
				t.Fatal("no TLS configuration")
			}
			if cfg.InsecureSkipVerify {
				t.Error("InsecureSkipVerify is set")
			}
			if cfg.MinVersion != tls.VersionTLS12 {
				t.Errorf("MinVersion = %#x, want TLS 1.2", cfg.MinVersion)
			}
			if cfg.ServerName != tc.wantName {
				t.Errorf("ServerName = %q, want %q", cfg.ServerName, tc.wantName)
			}
			if (cfg.RootCAs != nil) != tc.wantCustomCA {
				t.Errorf("RootCAs set = %v, want %v (nil means the system pool)", cfg.RootCAs != nil, tc.wantCustomCA)
			}
		})
	}
	if r := newTCP(t, TCPOptions{Address: "192.0.2.10:9000"}); r.tlsConf != nil {
		t.Error("TLS configured although not requested")
	}
}

func TestNewTCPValidation(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.pem")
	must(t, os.WriteFile(garbage, []byte("this is not a certificate\n"), 0o600))
	empty := filepath.Join(dir, "empty.pem")
	must(t, os.WriteFile(empty, nil, 0o600))

	bad := []struct {
		name string
		opts TCPOptions
	}{
		{"empty address", TCPOptions{}},
		{"no port", TCPOptions{Address: "collector.example.net"}},
		{"port zero", TCPOptions{Address: "collector.example.net:0"}},
		{"port too large", TCPOptions{Address: "collector.example.net:70000"}},
		{"named port", TCPOptions{Address: "collector.example.net:http"}},
		{"no host", TCPOptions{Address: ":9000"}},
		{"unbracketed IPv6", TCPOptions{Address: "2001:db8::10:9000"}},
		{"CA file without TLS", TCPOptions{Address: "192.0.2.10:9000", CAFile: garbage}},
		{"server name without TLS", TCPOptions{Address: "192.0.2.10:9000", ServerName: "x"}},
		{"missing CA file", TCPOptions{Address: "192.0.2.10:9000", TLS: true, CAFile: filepath.Join(dir, "missing.pem")}},
		{"CA file is not PEM", TCPOptions{Address: "192.0.2.10:9000", TLS: true, CAFile: garbage}},
		{"empty CA file", TCPOptions{Address: "192.0.2.10:9000", TLS: true, CAFile: empty}},
		{"negative queue", TCPOptions{Address: "192.0.2.10:9000", QueueSize: -1}},
		{"negative retries", TCPOptions{Address: "192.0.2.10:9000", MaxRetries: -1}},
		{"negative connect timeout", TCPOptions{Address: "192.0.2.10:9000", ConnectTimeout: -time.Second}},
		{"negative write timeout", TCPOptions{Address: "192.0.2.10:9000", WriteTimeout: -time.Second}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if r, err := NewTCP(tc.opts); err == nil {
				r.Shutdown(context.Background())
				t.Fatal("NewTCP succeeded")
			}
		})
	}
	good := []TCPOptions{
		{Address: "192.0.2.10:9000"},
		{Address: "collector.example.net:9000"},
		{Address: "[2001:db8::10]:9000", TLS: true},
	}
	for _, opts := range good {
		r, err := NewTCP(opts)
		if err != nil {
			t.Errorf("NewTCP(%q): %v", opts.Address, err)
			continue
		}
		if st := r.Stats(); st.QueueCap != 10000 {
			t.Errorf("default queue size = %d, want 10000", st.QueueCap)
		}
		shutdownRemote(t, r)
	}
}
