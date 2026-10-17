package output

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultQueueSize = 10000
	defaultTimeout   = 5 * time.Second
	// shutdownGrace is how long Shutdown waits for the worker after it has
	// cancelled in-flight work. Cancellation is immediate for every operation
	// the workers perform, so this only guards against a bug.
	shutdownGrace = 2 * time.Second
)

// Remote is one asynchronous, best-effort output. Each Remote owns a bounded
// queue and exactly one worker goroutine.
type Remote interface {
	// Name is "tcp", "udp" or "webhook".
	Name() string
	// Enqueue hands one serialized JSONL line to the output. It never blocks.
	// false means the event was not accepted (queue full, too large for UDP,
	// or output shut down) and has been counted as dropped; the other outputs
	// are unaffected. line is retained until delivered, so the caller must not
	// modify it.
	Enqueue(eventID string, line []byte) bool
	// Stats returns a snapshot of the counters.
	Stats() RemoteStats
	// Shutdown stops accepting events, delivers what is queued until ctx is
	// done, then cancels in-flight work, counts and drops the rest and stops
	// all goroutines. It returns the number of accepted events that were not
	// delivered. It is idempotent: later calls return the same number.
	Shutdown(ctx context.Context) (dropped int)
}

// RemoteStats are counters of one Remote for the current run.
type RemoteStats struct {
	QueueLen, QueueCap int
	// HandedOver counts events written to the socket without error (TCP, UDP;
	// this is not an acknowledgement by the receiver) or answered with HTTP
	// 2xx (webhook).
	HandedOver int64
	// DroppedQueueFull counts events rejected because the queue was full.
	DroppedQueueFull int64
	// DroppedTooLarge counts events above the UDP payload limit.
	DroppedTooLarge int64
	// DroppedShutdown counts events lost to Shutdown: accepted events that
	// were not delivered (the number Shutdown returns) plus events offered
	// after Shutdown began.
	DroppedShutdown int64
	// Failed counts events given up after exhausting the retries, events that
	// failed for a non-retriable reason and UDP events lost to transport
	// errors.
	Failed int64
	// Retries counts repeated delivery attempts of events.
	Retries int64
	// LastError is the most recent transport error, redacted and bounded. It
	// is kept after the output recovers.
	LastError string
}

// Hooks replace slow or non-deterministic parts for tests. Production callers
// leave it at its zero value.
type Hooks struct {
	// BackoffBase and BackoffMax replace the 1s / 30s backoff bounds.
	BackoffBase, BackoffMax time.Duration
	// BackoffJitter replaces the +-20% jitter (0.2). A negative value
	// disables jitter.
	BackoffJitter float64
	// Sleep replaces the cancellable wait between attempts.
	Sleep func(ctx context.Context, d time.Duration) error
	// Now replaces the clock used for Retry-After dates, UDP reconnect
	// backoff and log rate limiting.
	Now func() time.Time
	// Dial replaces the network dialer (TCP, UDP, and webhook connections).
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// RootCAs replaces the system pool for webhook TLS verification.
	RootCAs *x509.CertPool
	// Transport replaces the webhook HTTP transport.
	Transport http.RoundTripper
}

// attemptResult is the outcome of one delivery attempt.
type attemptResult struct {
	err       error         // nil: delivered
	retryable bool          // whether a failed attempt may be repeated
	minWait   time.Duration // lower bound for the wait before the next attempt
}

// engine is the machinery shared by all transports: the bounded queue, the
// single worker, retry/backoff, counters, error aggregation and shutdown.
type engine struct {
	name string
	log  *slog.Logger
	q    *queue

	ctx     context.Context // cancelled to abort in-flight work
	cancel  context.CancelFunc
	aborted atomic.Bool   // Shutdown ran into its deadline and cancelled ctx
	done    chan struct{} // closed when the worker and its helpers have exited
	helpers sync.WaitGroup

	maxRetries int
	backoff    backoffPolicy
	sleep      func(context.Context, time.Duration) error
	now        func() time.Time
	rep        *errReporter

	handedOver, droppedFull, droppedLarge, failed, retries atomic.Int64
	// abandoned counts accepted events that Shutdown could not deliver;
	// rejectedClosed counts events offered after Shutdown began.
	abandoned, rejectedClosed atomic.Int64
}

type engineConfig struct {
	name       string
	queueSize  int
	maxRetries int
	logger     *slog.Logger
	hooks      Hooks
	secrets    []string // removed from every logged or stored error text
}

func newEngine(cfg engineConfig) *engine {
	log := cfg.logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	log = log.With("output", cfg.name)
	now := cfg.hooks.Now
	if now == nil {
		now = time.Now
	}
	sleep := cfg.hooks.Sleep
	if sleep == nil {
		sleep = sleepContext
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &engine{
		name: cfg.name, log: log, q: newQueue(cfg.queueSize),
		ctx: ctx, cancel: cancel, done: make(chan struct{}),
		maxRetries: cfg.maxRetries, backoff: newBackoff(cfg.hooks), sleep: sleep, now: now,
	}
	e.rep = newErrReporter(log, now, newScrubber(cfg.secrets))
	return e
}

// start launches the worker. handle delivers one item and blocks until it is
// done or e.ctx is cancelled; cleanup closes the transport's resources.
func (e *engine) start(handle func(item), cleanup func()) {
	go func() {
		defer close(e.done)
		defer e.helpers.Wait() // helpers end once cleanup closed their connections
		defer e.cancel()       // after cleanup, so abort hooks cannot race with a graceful close
		defer cleanup()
		defer e.dropQueued()
		for {
			it, ok := e.q.pop(e.ctx)
			if !ok {
				return
			}
			handle(it)
		}
	}()
}

// dropQueued counts what an aborted shutdown leaves behind.
func (e *engine) dropQueued() {
	if n := e.q.drain(); n > 0 {
		e.abandoned.Add(int64(n))
	}
}

func (e *engine) Name() string { return e.name }

// enqueue is the shared, non-blocking admission of an event; the transports
// expose it as Enqueue after their own admission checks.
func (e *engine) enqueue(eventID string, line []byte) bool {
	switch e.q.push(item{id: eventID, line: line}) {
	case pushed:
		return true
	case pushFull:
		e.droppedFull.Add(1)
	default:
		e.rejectedClosed.Add(1)
	}
	return false
}

func (e *engine) Stats() RemoteStats {
	return RemoteStats{
		QueueLen:         e.q.length(),
		QueueCap:         e.q.limit,
		HandedOver:       e.handedOver.Load(),
		DroppedQueueFull: e.droppedFull.Load(),
		DroppedTooLarge:  e.droppedLarge.Load(),
		DroppedShutdown:  e.abandoned.Load() + e.rejectedClosed.Load(),
		Failed:           e.failed.Load(),
		Retries:          e.retries.Load(),
		LastError:        e.rep.lastError(),
	}
}

func (e *engine) Shutdown(ctx context.Context) int {
	if ctx == nil {
		ctx = context.Background()
	}
	e.q.close()
	select {
	case <-e.done:
	case <-ctx.Done():
		e.aborted.Store(true)
		e.cancel()
		timer := time.NewTimer(shutdownGrace)
		defer timer.Stop()
		select {
		case <-e.done:
		case <-timer.C:
			e.log.Error("output worker did not stop after cancellation")
			return int(e.abandoned.Load()) + e.q.length()
		}
	}
	return int(e.abandoned.Load())
}

// deliver runs the shared retry policy for TCP and webhook: at most
// maxRetries+1 attempts with exponential backoff in between. The next event is
// only taken once this one is delivered or given up, which preserves order.
func (e *engine) deliver(it item, attempt func(ctx context.Context, it item) attemptResult) {
	for n := 0; ; n++ {
		if n > 0 {
			e.retries.Add(1)
		}
		res := attempt(e.ctx, it)
		if res.err == nil {
			e.handedOver.Add(1)
			e.rep.success()
			return
		}
		if e.ctx.Err() != nil {
			// Interrupted by Shutdown: not a transport failure.
			e.abandoned.Add(1)
			return
		}
		if !res.retryable || n >= e.maxRetries {
			// Record the error before counting the failure, so a Stats reader
			// that sees the count also sees its cause.
			if !res.retryable {
				e.rep.failure(fmt.Errorf("event dropped, not retriable: %w", res.err))
			} else {
				e.rep.failure(fmt.Errorf("event dropped after %d attempts: %w", n+1, res.err))
			}
			e.failed.Add(1)
			return
		}
		e.rep.failure(res.err)
		wait := max(e.backoff.delay(n+1), res.minWait)
		if err := e.sleep(e.ctx, wait); err != nil {
			e.abandoned.Add(1)
			return
		}
	}
}

// Option validation shared by the constructors.

func queueSizeOrDefault(n int) (int, error) {
	switch {
	case n < 0:
		return 0, fmt.Errorf("queue size must not be negative (got %d)", n)
	case n == 0:
		return defaultQueueSize, nil
	}
	return n, nil
}

func durationOrDefault(what string, d, def time.Duration) (time.Duration, error) {
	switch {
	case d < 0:
		return 0, fmt.Errorf("%s must not be negative (got %s)", what, d)
	case d == 0:
		return def, nil
	}
	return d, nil
}

func checkRetries(n int) error {
	if n < 0 {
		return errors.New("max retries must not be negative")
	}
	return nil
}
