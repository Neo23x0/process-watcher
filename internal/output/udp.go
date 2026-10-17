package output

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"syscall"
	"time"
)

const (
	defaultUDPMaxBytes = 8192
	maxUDPPayload      = 65507 // largest IPv4 UDP payload
)

// UDPOptions configures the UDP output. Zero values select MaxBytes 8192,
// QueueSize 10000 and 5s timeouts. UDP never retransmits, so there is no
// retry setting.
type UDPOptions struct {
	// Address is host:port; the name is resolved again whenever the socket is
	// re-established.
	Address string
	// MaxBytes is the largest event (including the trailing newline) that is
	// sent. Larger events are dropped for UDP only, never truncated or split.
	MaxBytes int

	QueueSize      int
	ConnectTimeout time.Duration // name resolution and socket setup
	WriteTimeout   time.Duration // per datagram
	Logger         *slog.Logger

	Hooks Hooks
}

// udpRemote sends exactly one event per datagram. There is no retransmission:
// after a DNS or socket error the socket is closed and re-established on a
// later event, with exponential backoff during which events are dropped.
type udpRemote struct {
	*engine
	address        string
	maxBytes       int
	connectTimeout time.Duration
	writeTimeout   time.Duration
	dial           func(ctx context.Context, network, address string) (net.Conn, error)

	// Owned by the worker goroutine.
	conn     net.Conn
	failures int       // consecutive transport failures
	retryAt  time.Time // no reconnect before this time
}

var _ Remote = (*udpRemote)(nil)

// NewUDP starts a UDP output. It does not contact the network.
func NewUDP(opts UDPOptions) (Remote, error) {
	if _, err := checkHostPort(opts.Address); err != nil {
		return nil, fmt.Errorf("udp output: %w", err)
	}
	maxBytes := opts.MaxBytes
	switch {
	case maxBytes == 0:
		maxBytes = defaultUDPMaxBytes
	case maxBytes < 0 || maxBytes > maxUDPPayload:
		return nil, fmt.Errorf("udp output: max bytes must be between 1 and %d (got %d)", maxUDPPayload, maxBytes)
	}
	qs, err := queueSizeOrDefault(opts.QueueSize)
	if err != nil {
		return nil, fmt.Errorf("udp output: %w", err)
	}
	ct, err := durationOrDefault("connect timeout", opts.ConnectTimeout, defaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("udp output: %w", err)
	}
	wt, err := durationOrDefault("write timeout", opts.WriteTimeout, defaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("udp output: %w", err)
	}
	u := &udpRemote{address: opts.Address, maxBytes: maxBytes, connectTimeout: ct, writeTimeout: wt, dial: opts.Hooks.Dial}
	if u.dial == nil {
		u.dial = (&net.Dialer{Timeout: ct}).DialContext
	}
	u.engine = newEngine(engineConfig{name: "udp", queueSize: qs, logger: opts.Logger, hooks: opts.Hooks})
	u.start(u.handle, u.cleanup)
	return u, nil
}

// Enqueue drops events above MaxBytes right away; they would never fit into
// one datagram and must not be split.
func (u *udpRemote) Enqueue(eventID string, line []byte) bool {
	if len(line) > u.maxBytes {
		u.droppedLarge.Add(1)
		return false
	}
	return u.enqueue(eventID, line)
}

func (u *udpRemote) handle(it item) {
	now := u.now()
	if u.conn == nil {
		if now.Before(u.retryAt) {
			// Reconnect backoff: drop instead of queueing without bound.
			u.failed.Add(1)
			return
		}
		c, err := u.connect()
		if err != nil {
			u.fail(err, now)
			return
		}
		u.conn = c
	}
	_ = u.conn.SetWriteDeadline(time.Now().Add(u.writeTimeout))
	n, err := u.conn.Write(it.line)
	switch {
	case err == nil && n == len(it.line):
		u.handedOver.Add(1)
		u.failures = 0
		u.rep.success()
	case errors.Is(err, syscall.EMSGSIZE):
		// Too big for this socket or path; the socket itself is fine.
		u.droppedLarge.Add(1)
	default:
		if err == nil {
			err = io.ErrShortWrite
		}
		_ = u.conn.Close()
		u.conn = nil
		u.fail(fmt.Errorf("send to %s: %w", u.address, err), now)
	}
}

func (u *udpRemote) connect() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(u.ctx, u.connectTimeout)
	defer cancel()
	c, err := u.dial(ctx, "udp", u.address)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", u.address, err)
	}
	return c, nil
}

// fail counts the event as failed and schedules the next reconnect.
func (u *udpRemote) fail(err error, now time.Time) {
	if u.ctx.Err() != nil {
		u.abandoned.Add(1)
		return
	}
	u.failures++
	u.retryAt = now.Add(u.backoff.delay(u.failures))
	u.rep.failure(err)
	u.failed.Add(1)
}

func (u *udpRemote) cleanup() {
	if u.conn != nil {
		_ = u.conn.Close()
		u.conn = nil
	}
}
