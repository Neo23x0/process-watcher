package output

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// TCPOptions configures the TCP output. Zero values select QueueSize 10000
// and 5s timeouts; MaxRetries 0 means a single attempt per event.
type TCPOptions struct {
	// Address is host:port with an IPv4/IPv6 literal or a DNS name; names are
	// resolved again on every new connection.
	Address string
	// TLS enables TLS with regular certificate and hostname verification.
	TLS bool
	// CAFile is a PEM bundle that replaces the system trust store (requires
	// TLS).
	CAFile string
	// ServerName overrides the name verified in the certificate (requires
	// TLS); it defaults to the host part of Address.
	ServerName string

	QueueSize      int
	MaxRetries     int
	ConnectTimeout time.Duration // dial plus TLS handshake
	WriteTimeout   time.Duration // per event
	Logger         *slog.Logger

	Hooks Hooks
}

// tcpRemote keeps one persistent connection and writes each event as one
// newline terminated line. A failed attempt closes the connection and retries
// the whole line, with identical bytes, on a new one.
type tcpRemote struct {
	*engine
	address        string
	connectTimeout time.Duration
	writeTimeout   time.Duration
	dial           func(ctx context.Context, network, address string) (net.Conn, error)
	tlsConf        *tls.Config // nil: plaintext

	curMu sync.Mutex
	cur   *tcpConn // replaced only by the worker goroutine
}

// gracefulCloseWait bounds the TLS close_notify exchange at the end of a
// healthy run; crypto/tls would otherwise wait up to 5s for a stalled peer.
const gracefulCloseWait = 500 * time.Millisecond

// tcpConn is a connection plus a watcher that notices when the peer closes it.
type tcpConn struct {
	net.Conn               // used for I/O: the TLS session or the raw connection
	raw      net.Conn      // the underlying transport connection
	secure   bool          // Conn is a TLS session on top of raw
	dead     chan struct{} // closed when reading the connection failed or hit EOF
	stop     func() bool   // deregisters the abort hook
}

var _ Remote = (*tcpRemote)(nil)

// NewTCP starts a TCP output. It does not contact the network.
func NewTCP(opts TCPOptions) (Remote, error) {
	host, err := checkHostPort(opts.Address)
	if err != nil {
		return nil, fmt.Errorf("tcp output: %w", err)
	}
	if !opts.TLS && (opts.CAFile != "" || opts.ServerName != "") {
		return nil, errors.New("tcp output: ca_file and server_name require tls to be enabled")
	}
	qs, err := queueSizeOrDefault(opts.QueueSize)
	if err != nil {
		return nil, fmt.Errorf("tcp output: %w", err)
	}
	if err := checkRetries(opts.MaxRetries); err != nil {
		return nil, fmt.Errorf("tcp output: %w", err)
	}
	ct, err := durationOrDefault("connect timeout", opts.ConnectTimeout, defaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("tcp output: %w", err)
	}
	wt, err := durationOrDefault("write timeout", opts.WriteTimeout, defaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("tcp output: %w", err)
	}
	t := &tcpRemote{address: opts.Address, connectTimeout: ct, writeTimeout: wt, dial: opts.Hooks.Dial}
	if t.dial == nil {
		t.dial = (&net.Dialer{Timeout: ct}).DialContext
	}
	if opts.TLS {
		if t.tlsConf, err = newTLSConfig(host, opts.CAFile, opts.ServerName); err != nil {
			return nil, fmt.Errorf("tcp output: %w", err)
		}
	}
	t.engine = newEngine(engineConfig{
		name: "tcp", queueSize: qs, maxRetries: opts.MaxRetries, logger: opts.Logger, hooks: opts.Hooks,
	})
	t.start(func(it item) { t.deliver(it, t.attempt) }, t.cleanup)
	return t, nil
}

func (t *tcpRemote) Enqueue(eventID string, line []byte) bool { return t.enqueue(eventID, line) }

// attempt writes the complete line, connecting first if necessary.
func (t *tcpRemote) attempt(ctx context.Context, it item) attemptResult {
	c, err := t.conn(ctx)
	if err != nil {
		return attemptResult{err: err, retryable: true}
	}
	_ = c.SetWriteDeadline(time.Now().Add(t.writeTimeout))
	if err := writeFull(c, it.line); err != nil {
		// A partial line may be on the wire; the stream is unusable.
		t.drop(c, false)
		return attemptResult{err: fmt.Errorf("write to %s: %w", t.address, err), retryable: true}
	}
	return attemptResult{}
}

// conn returns the live connection or establishes a new one. A connection
// whose peer has closed it is replaced before anything is written to it, so
// the first event after a receiver restart is not lost to a dead socket.
func (t *tcpRemote) conn(ctx context.Context) (*tcpConn, error) {
	if c := t.current(); c != nil {
		select {
		case <-c.dead:
			t.drop(c, false)
		default:
			return c, nil
		}
	}
	cctx, cancel := context.WithTimeout(ctx, t.connectTimeout)
	defer cancel()
	// The name is resolved by the dialer, i.e. again for every connection.
	raw, err := t.dial(cctx, "tcp", t.address)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", t.address, err)
	}
	nc := raw
	if t.tlsConf != nil {
		tc := tls.Client(raw, t.tlsConf.Clone())
		if err := tc.HandshakeContext(cctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("TLS handshake with %s: %w", t.address, err)
		}
		nc = tc
	}
	c := &tcpConn{Conn: nc, raw: raw, secure: t.tlsConf != nil, dead: make(chan struct{})}
	// Closing the transport connection is how Shutdown interrupts a blocked
	// read or write. It is closed directly: tls.Conn.Close would first try to
	// send close_notify, which can block on a stalled peer.
	c.stop = context.AfterFunc(t.ctx, func() { _ = raw.Close() })
	t.curMu.Lock()
	t.cur = c
	t.curMu.Unlock()
	t.helpers.Add(1)
	go t.watch(c)
	return c, nil
}

// watch reads and discards whatever the peer sends. A collector is not
// expected to send anything, but reading is the only way to learn promptly
// that it closed the connection (FIN/RST) while nothing is being written.
func (t *tcpRemote) watch(c *tcpConn) {
	defer t.helpers.Done()
	defer close(c.dead)
	var buf [256]byte
	for empty := 0; ; {
		n, err := c.Conn.Read(buf[:])
		if err != nil {
			return
		}
		if n == 0 {
			if empty++; empty > 100 {
				return
			}
			continue
		}
		empty = 0
	}
}

func (t *tcpRemote) current() *tcpConn {
	t.curMu.Lock()
	defer t.curMu.Unlock()
	return t.cur
}

// drop closes c and forgets it. A broken or abandoned connection is closed
// abruptly; only the end of a healthy run says goodbye (TLS close_notify).
func (t *tcpRemote) drop(c *tcpConn, graceful bool) {
	c.stop()
	if graceful && c.secure {
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			_ = c.Conn.Close()
		}()
		timer := time.NewTimer(gracefulCloseWait)
		defer timer.Stop()
		select {
		case <-closed:
		case <-timer.C:
			_ = c.raw.Close() // unblocks the goroutine above
			<-closed
		}
	} else {
		_ = c.raw.Close()
	}
	t.curMu.Lock()
	if t.cur == c {
		t.cur = nil
	}
	t.curMu.Unlock()
}

func (t *tcpRemote) cleanup() {
	if c := t.current(); c != nil {
		t.drop(c, !t.aborted.Load())
	}
}

// peerClosed reports whether the current connection was closed by the peer.
func (t *tcpRemote) peerClosed() bool {
	c := t.current()
	if c == nil {
		return false
	}
	select {
	case <-c.dead:
		return true
	default:
		return false
	}
}

// writeFull writes all of p, looping over short writes.
func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > len(p) {
			n = len(p)
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// checkHostPort validates "host:port" and returns the host.
func checkHostPort(addr string) (string, error) {
	if addr == "" {
		return "", errors.New("address is empty")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return "", fmt.Errorf("address %q must have the form host:port", addr)
	}
	if p, err := strconv.ParseUint(port, 10, 16); err != nil || p == 0 {
		return "", fmt.Errorf("address %q has an invalid port", addr)
	}
	return host, nil
}

// newTLSConfig builds the client configuration: TLS 1.2 or newer, normal
// certificate and hostname verification (never InsecureSkipVerify), the CA
// bundle from caFile instead of the system pool when given.
func newTLSConfig(host, caFile, serverName string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if serverName != "" {
		cfg.ServerName = serverName
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %q contains no valid PEM certificate", caFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}
