package output

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- queue ---------------------------------------------------------------------

func TestQueueFIFOBoundGrowthAndWraparound(t *testing.T) {
	q := newQueue(200)
	ctx := context.Background()
	next, want := 0, 0
	// Interleave pushes and pops so the ring wraps around while it grows.
	for round := 0; round < 50; round++ {
		for i := 0; i < 7; i++ {
			if q.push(item{id: fmt.Sprint(next)}) != pushed {
				t.Fatalf("push %d refused below the bound", next)
			}
			next++
		}
		for i := 0; i < 5; i++ {
			it, ok := q.pop(ctx)
			if !ok || it.id != fmt.Sprint(want) {
				t.Fatalf("pop = %q, %v; want %d", it.id, ok, want)
			}
			want++
		}
	}
	if q.length() != next-want {
		t.Fatalf("length = %d, want %d", q.length(), next-want)
	}
	for q.length() < 200 {
		if q.push(item{id: fmt.Sprint(next)}) != pushed {
			t.Fatal("push refused below the bound")
		}
		next++
	}
	if q.push(item{}) != pushFull {
		t.Fatal("push beyond the bound was accepted")
	}
	if n := q.drain(); n != 200 || q.length() != 0 {
		t.Fatalf("drain = %d, length %d", n, q.length())
	}
}

func TestQueueCloseAndCancel(t *testing.T) {
	q := newQueue(4)
	q.push(item{id: "a"})
	q.close()
	if q.push(item{id: "late"}) != pushClosed {
		t.Fatal("push after close was accepted")
	}
	if it, ok := q.pop(context.Background()); !ok || it.id != "a" {
		t.Fatal("queued item lost by close")
	}
	if _, ok := q.pop(context.Background()); ok {
		t.Fatal("pop on a closed, empty queue did not report the end")
	}

	q = newQueue(4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool)
	go func() { _, ok := q.pop(ctx); done <- ok }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("pop returned an item after cancellation")
		}
	case <-time.After(testWait):
		t.Fatal("pop did not return after cancellation")
	}
	// A cancelled context wins over queued items: shutdown must not drain.
	q.push(item{id: "x"})
	if _, ok := q.pop(ctx); ok {
		t.Fatal("pop returned an item although the context is cancelled")
	}
}

func TestQueueLargeLimitAllocatesLazily(t *testing.T) {
	q := newQueue(100_000_000)
	if len(q.buf) > 64 {
		t.Fatalf("initial storage = %d slots for a huge limit", len(q.buf))
	}
}

// --- targets for cross-transport tests ---------------------------------------------

// target is a Remote wired to a healthy local receiver.
type target struct {
	name      string
	remote    Remote
	delivered func() [][]byte // events received so far, in arrival order
}

func splitLines(b []byte) [][]byte {
	var lines [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			break
		}
		lines = append(lines, b[:i+1])
		b = b[i+1:]
	}
	return lines
}

// newTargets creates a plain TCP, a TLS TCP, a UDP, an HTTP and an HTTPS
// target, each with its own healthy receiver.
func newTargets(t *testing.T, queueSize int) []target {
	t.Helper()
	ca := newTestCA(t, "test CA")
	nb, na := validNow()
	tlsSink := newTCPSink(t, &tls.Config{Certificates: []tls.Certificate{ca.issue(t, []string{"collector.test"}, nil, nb, na)}}, nil)
	tcpSink := newTCPSink(t, nil, nil)
	udp := newUDPSink(t)
	hook := newHookServer(t, false, nil)
	hookTLS := newHookServer(t, true, nil)
	pool := x509.NewCertPool()
	pool.AddCert(hookTLS.Certificate())

	bodies := func(hs *hookServer) func() [][]byte {
		return func() [][]byte {
			var out [][]byte
			for _, r := range hs.Requests() {
				out = append(out, r.Body)
			}
			return out
		}
	}
	return []target{
		{"tcp", newTCP(t, TCPOptions{Address: tcpSink.Addr(), QueueSize: queueSize}),
			func() [][]byte { return splitLines(tcpSink.All()) }},
		{"tcp+tls", newTCP(t, TCPOptions{Address: tlsSink.Addr(), TLS: true, CAFile: ca.writePEM(t),
			ServerName: "collector.test", QueueSize: queueSize}),
			func() [][]byte { return splitLines(tlsSink.All()) }},
		{"udp", newUDP(t, UDPOptions{Address: udp.Addr(), QueueSize: queueSize}),
			func() [][]byte { return udp.Packets() }},
		{"webhook", newWebhook(t, WebhookOptions{URL: hook.URL + "/hook", QueueSize: queueSize}), bodies(hook)},
		{"webhook+tls", newWebhook(t, WebhookOptions{URL: hookTLS.URL + "/hook", QueueSize: queueSize,
			Hooks: Hooks{RootCAs: pool}}), bodies(hookTLS)},
	}
}

func sortedCopy(in [][]byte) [][]byte {
	out := append([][]byte(nil), in...)
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

// eventLine builds a varied, realistic JSONL line.
func eventLine(i int) (id string, line []byte) {
	id = fmt.Sprintf("0b9f6c1e-0000-4000-8000-%012d", i)
	args := []string{`sh`, `-c`, `echo "quoted" \n new line   é 日本語`}
	line = []byte(fmt.Sprintf(`{"schema_version":1,"event_id":%q,"sequence":%d,"process":{"argv":[%q,%q,%q]}}`+"\n",
		id, i, args[0], args[1], args[2]))
	return id, line
}

func TestAllTransportsDeliverByteIdenticalEvents(t *testing.T) {
	const n = 60
	targets := newTargets(t, 1000)
	var want [][]byte
	for i := 0; i < n; i++ {
		id, line := eventLine(i)
		want = append(want, line)
		for _, tg := range targets { // the same slice goes to every output
			if !tg.remote.Enqueue(id, line) {
				t.Fatalf("%s rejected event %d", tg.name, i)
			}
		}
	}
	for _, tg := range targets {
		t.Run(tg.name, func(t *testing.T) {
			waitFor(t, "all events", func() bool { return len(tg.delivered()) == n })
			got, wantLines := tg.delivered(), want
			if tg.name == "udp" { // datagram order is not guaranteed
				got = sortedCopy(got)
				wantLines = sortedCopy(want)
			}
			for i := range got {
				if !bytes.Equal(got[i], wantLines[i]) {
					t.Fatalf("event %d differs from the serialized line", i)
				}
			}
			// The receiver may have seen the last event a moment before the
			// sender processed the answer.
			waitFor(t, "HandedOver", func() bool { return tg.remote.Stats().HandedOver == n })
			st := tg.remote.Stats()
			if st.Failed != 0 || st.Retries != 0 {
				t.Errorf("stats = %+v", st)
			}
		})
	}
	for _, tg := range targets {
		shutdownRemote(t, tg.remote)
	}
	assertNoLeaks(t)
}

// An event above the UDP limit is dropped for UDP only; TCP and the webhook
// still deliver the very same bytes.
func TestOversizeEventDropsOnlyUDP(t *testing.T) {
	tcpSink := newTCPSink(t, nil, nil)
	udp := newUDPSink(t)
	hook := newHookServer(t, false, nil)
	tcpR := newTCP(t, TCPOptions{Address: tcpSink.Addr()})
	udpR := newUDP(t, UDPOptions{Address: udp.Addr(), MaxBytes: 512})
	webR := newWebhook(t, WebhookOptions{URL: hook.URL})
	remotes := []Remote{tcpR, udpR, webR}

	ids := []string{"small-1", "big", "small-2"}
	lines := [][]byte{makeLine(ids[0], 300), makeLine(ids[1], 4000), makeLine(ids[2], 400)}
	var wantStream []byte
	accepted := map[string][]bool{}
	for i, line := range lines {
		wantStream = append(wantStream, line...)
		for _, r := range remotes {
			accepted[r.Name()] = append(accepted[r.Name()], r.Enqueue(ids[i], line))
		}
	}
	tcpSink.waitBytes(t, len(wantStream))
	udp.waitPackets(t, 2)
	waitFor(t, "webhook requests", func() bool { return hook.Count() == 3 })
	for _, r := range remotes {
		shutdownRemote(t, r)
	}

	if fmt.Sprint(accepted["udp"]) != "[true false true]" || fmt.Sprint(accepted["tcp"]) != "[true true true]" ||
		fmt.Sprint(accepted["webhook"]) != "[true true true]" {
		t.Errorf("Enqueue results = %v", accepted)
	}
	if !bytes.Equal(tcpSink.All(), wantStream) {
		t.Error("TCP stream differs")
	}
	for i, req := range hook.Requests() {
		if !bytes.Equal(req.Body, lines[i]) {
			t.Errorf("webhook body %d differs (%d bytes)", i, len(req.Body))
		}
	}
	pk := udp.Packets()
	if len(pk) != 2 || !bytes.Equal(pk[0], lines[0]) || !bytes.Equal(pk[1], lines[2]) {
		t.Errorf("UDP receiver got %d datagrams, want the two small events", len(pk))
	}
	if st := udpR.Stats(); st.DroppedTooLarge != 1 || st.HandedOver != 2 || st.Failed != 0 {
		t.Errorf("udp stats = %+v", st)
	}
	for _, r := range []Remote{tcpR, webR} {
		if st := r.Stats(); st.DroppedTooLarge != 0 || st.HandedOver != 3 {
			t.Errorf("%s stats = %+v", r.Name(), st)
		}
	}
}

// --- full queues and hanging targets ----------------------------------------------------

// hangingTarget is a Remote whose single worker is stuck in a delivery.
type hangingTarget struct {
	name   string
	remote Remote
	// blocked returns once the worker is stuck delivering the first event.
	blocked func()
}

func newHangingTCP(t *testing.T, queueSize int) hangingTarget {
	started := make(chan struct{})
	c := newFakeConn()
	c.writeFn = blockUntilClosed(started)
	dial := func(context.Context, string, string) (net.Conn, error) { return c, nil }
	r := newTCP(t, TCPOptions{Address: "collector.example.test:9000", QueueSize: queueSize, Hooks: Hooks{Dial: dial}})
	return hangingTarget{"tcp", r, func() { <-started }}
}

func newHangingWebhook(t *testing.T, queueSize int) hangingTarget {
	entered := make(chan struct{})
	var once sync.Once
	srv := newHookServer(t, false, func(w http.ResponseWriter, r *http.Request, n int) {
		once.Do(func() { close(entered) })
		select { // never answers
		case <-r.Context().Done():
		case <-time.After(30 * time.Second):
		}
	})
	r := newWebhook(t, WebhookOptions{URL: srv.URL, QueueSize: queueSize, Timeout: 30 * time.Second})
	return hangingTarget{"webhook", r, func() { <-entered }}
}

func TestEnqueueNeverBlocksAndQueueStaysBounded(t *testing.T) {
	const queueSize, flood = 5, 2000
	for _, mk := range []func(*testing.T, int) hangingTarget{newHangingTCP, newHangingWebhook} {
		tg := mk(t, queueSize)
		t.Run(tg.name, func(t *testing.T) {
			r := tg.remote
			if !r.Enqueue("first", makeLine("first", 200)) {
				t.Fatal("first event rejected")
			}
			tg.blocked() // the worker is now stuck in this event

			var accepted, maxLen int
			start := time.Now()
			for i := 0; i < flood; i++ {
				if r.Enqueue(fmt.Sprint(i), makeLine("flood", 200)) {
					accepted++
				}
				if l := r.Stats().QueueLen; l > maxLen {
					maxLen = l
				}
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("%d Enqueue calls took %s against a hanging target", flood, d)
			}
			if accepted != queueSize || maxLen != queueSize {
				t.Errorf("accepted = %d, max queue length = %d; both must equal the bound %d", accepted, maxLen, queueSize)
			}
			st := r.Stats()
			if st.QueueCap != queueSize || st.QueueLen != queueSize || st.DroppedQueueFull != flood-queueSize {
				t.Errorf("stats = %+v", st)
			}

			// Shutdown abandons the stuck event and the queued ones, and says so.
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if dropped := r.Shutdown(ctx); dropped != queueSize+1 {
				t.Errorf("Shutdown dropped %d, want %d (queued + in flight)", dropped, queueSize+1)
			}
		})
	}
}

// A real receiver that accepts the connection but never reads: once the
// kernel buffers are full the worker is stuck, the queue fills up and Enqueue
// must stay instantaneous.
func TestEnqueueStaysNonBlockingWithStalledTCPServer(t *testing.T) {
	const queueSize = 5
	release := make(chan struct{})
	sink := newTCPSink(t, nil, func(idx int, c net.Conn, sc *sinkConn) { <-release })
	t.Cleanup(func() { close(release) }) // runs before the sink is closed
	r := newTCP(t, TCPOptions{Address: sink.Addr(), QueueSize: queueSize, WriteTimeout: time.Minute})
	line := makeLine("big", 1<<20)

	// Keep offering until the worker has been stuck for a while with a full queue.
	var lastHanded int64 = -1
	var stableSince time.Time
	waitFor(t, "the worker to get stuck behind the stalled receiver", func() bool {
		r.Enqueue("e", line)
		st := r.Stats()
		if st.QueueLen != queueSize {
			stableSince = time.Time{}
			return false
		}
		if stableSince.IsZero() || st.HandedOver != lastHanded {
			lastHanded, stableSince = st.HandedOver, time.Now()
			return false
		}
		return time.Since(stableSince) > 300*time.Millisecond
	})

	before := r.Stats().DroppedQueueFull
	start := time.Now()
	for i := 0; i < 5000; i++ {
		if r.Enqueue("e", line) {
			t.Fatal("an event was accepted beyond the queue bound")
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("5000 Enqueue calls took %s", d)
	}
	st := r.Stats()
	if st.QueueLen != queueSize || st.DroppedQueueFull-before != 5000 {
		t.Errorf("stats = %+v", st)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if dropped := r.Shutdown(ctx); dropped != queueSize+1 {
		t.Errorf("Shutdown dropped %d, want %d (queued + in flight)", dropped, queueSize+1)
	}
}

func TestHangingRemoteDoesNotSlowOthers(t *testing.T) {
	const n = 2000
	hang := newHangingWebhook(t, 50)
	sink := newTCPSink(t, nil, nil)
	healthy := newTCP(t, TCPOptions{Address: sink.Addr(), QueueSize: n})

	hang.remote.Enqueue("first", makeLine("first", 200))
	hang.blocked()

	var want []byte
	start := time.Now()
	for i := 0; i < n; i++ {
		id, line := eventLine(i)
		want = append(want, line...)
		hang.remote.Enqueue(id, line) // the integrator calls every output in turn
		if !healthy.Enqueue(id, line) {
			t.Fatalf("healthy output rejected event %d", i)
		}
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("fan-out took %s although one output hangs", d)
	}
	sink.waitBytes(t, len(want))
	if !bytes.Equal(sink.All(), want) {
		t.Fatal("healthy output lost or reordered events")
	}
	if st := hang.remote.Stats(); st.QueueLen > 50 || st.DroppedQueueFull == 0 {
		t.Errorf("hanging output stats = %+v", st)
	}
	waitFor(t, "HandedOver", func() bool { return healthy.Stats().HandedOver == n })
	if st := healthy.Stats(); st.DroppedQueueFull != 0 {
		t.Errorf("healthy output stats = %+v", st)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	hang.remote.Shutdown(ctx) // cancels the stuck request
}

// --- shutdown ---------------------------------------------------------------------------------

func TestShutdownDeliversQueuedEvents(t *testing.T) {
	const n = 300
	targets := newTargets(t, 1000)
	for _, tg := range targets {
		for i := 0; i < n; i++ {
			id, line := eventLine(i)
			if !tg.remote.Enqueue(id, line) {
				t.Fatalf("%s: event %d rejected", tg.name, i)
			}
		}
	}
	for _, tg := range targets {
		t.Run(tg.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), testWait)
			defer cancel()
			if dropped := tg.remote.Shutdown(ctx); dropped != 0 {
				t.Fatalf("Shutdown dropped %d events although the target is healthy", dropped)
			}
			st := tg.remote.Stats()
			if st.HandedOver != n || st.QueueLen != 0 {
				t.Errorf("stats after Shutdown = %+v, want everything handed over", st)
			}
			waitFor(t, "events at the receiver", func() bool { return len(tg.delivered()) == n })

			// Idempotent: repeating it changes nothing and returns at once.
			start := time.Now()
			if dropped := tg.remote.Shutdown(ctx); dropped != 0 || time.Since(start) > time.Second {
				t.Errorf("second Shutdown = %d after %s", dropped, time.Since(start))
			}
			// A late event is refused and counted, never queued.
			if tg.remote.Enqueue("late", makeLine("late", 100)) {
				t.Error("Enqueue after Shutdown succeeded")
			}
			if st := tg.remote.Stats(); st.DroppedShutdown != 1 || st.QueueLen != 0 {
				t.Errorf("stats after a late Enqueue = %+v", st)
			}
		})
	}
	assertNoLeaks(t)
}

// hangs describes a way for an output to be stuck, and how to build it.
type hangScenario struct {
	name string
	// build returns the remote and a function that returns once the worker is
	// stuck in its first event.
	build func(t *testing.T) (Remote, func())
}

func TestShutdownDeadlineAbortsInFlightWork(t *testing.T) {
	scenarios := []hangScenario{
		{"blocked TCP write", func(t *testing.T) (Remote, func()) {
			tg := newHangingTCP(t, 100)
			return tg.remote, tg.blocked
		}},
		{"unanswered webhook request", func(t *testing.T) (Remote, func()) {
			tg := newHangingWebhook(t, 100)
			return tg.remote, tg.blocked
		}},
		{"dial that never completes", func(t *testing.T) (Remote, func()) {
			entered := make(chan struct{})
			var once sync.Once
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				once.Do(func() { close(entered) })
				<-ctx.Done()
				return nil, ctx.Err()
			}
			r := newTCP(t, TCPOptions{Address: "collector.example.test:9000", QueueSize: 100,
				ConnectTimeout: time.Hour, Hooks: Hooks{Dial: dial}})
			return r, func() { <-entered }
		}},
		{"TLS handshake that never completes", func(t *testing.T) (Remote, func()) {
			sink := newTCPSink(t, nil, func(idx int, c net.Conn, sc *sinkConn) { _, _ = io.Copy(io.Discard, c) })
			ca := newTestCA(t, "ca")
			r := newTCP(t, TCPOptions{Address: sink.Addr(), TLS: true, CAFile: ca.writePEM(t), ServerName: "x.test",
				QueueSize: 100, ConnectTimeout: time.Hour})
			return r, func() { waitFor(t, "the handshake to start", func() bool { return sink.ConnCount() > 0 }) }
		}},
		{"worker waiting between retries", func(t *testing.T) (Remote, func()) {
			entered := make(chan struct{})
			var once sync.Once
			sleep := func(ctx context.Context, d time.Duration) error {
				once.Do(func() { close(entered) })
				return sleepContext(ctx, time.Hour)
			}
			dial := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("down (injected)") }
			r := newTCP(t, TCPOptions{Address: "collector.example.test:9000", QueueSize: 100, MaxRetries: 5,
				Hooks: Hooks{Dial: dial, Sleep: sleep}})
			return r, func() { <-entered }
		}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			r, stuck := sc.build(t)
			r.Enqueue("first", makeLine("first", 200))
			stuck()
			for i := 0; i < 9; i++ {
				r.Enqueue(fmt.Sprint(i), makeLine("queued", 200))
			}

			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			dropped := r.Shutdown(ctx)
			if d := time.Since(start); d > 1500*time.Millisecond {
				t.Errorf("Shutdown took %s with a 100ms deadline", d)
			}
			if dropped != 10 {
				t.Errorf("dropped = %d, want 10 (nine queued plus the one in flight)", dropped)
			}
			st := r.Stats()
			if st.DroppedShutdown != 10 || st.QueueLen != 0 || st.HandedOver != 0 || st.Failed != 0 {
				t.Errorf("stats = %+v; an interrupted delivery is neither a success nor a failure", st)
			}
			if again := r.Shutdown(ctx); again != 10 {
				t.Errorf("second Shutdown = %d, want the same count", again)
			}
			assertNoLeaks(t)
		})
	}
}

// With a slow target, Shutdown delivers what it can before the deadline and
// counts the rest, so that delivered + dropped always adds up.
func TestShutdownDrainsUntilDeadline(t *testing.T) {
	c := newFakeConn()
	c.writeFn = func(c *fakeConn, p []byte) (int, error) {
		time.Sleep(5 * time.Millisecond)
		if c.isClosed() {
			return 0, net.ErrClosed
		}
		c.record(p)
		return len(p), nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) { return c, nil }
	r := newTCP(t, TCPOptions{Address: "collector.example.test:9000", QueueSize: 1000, Hooks: Hooks{Dial: dial}})
	const n = 100
	for i := 0; i < n; i++ {
		r.Enqueue(fmt.Sprint(i), makeLine(fmt.Sprintf("e%03d", i), 100))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	dropped := r.Shutdown(ctx)
	st := r.Stats()
	if dropped == 0 || st.HandedOver == 0 {
		t.Errorf("dropped = %d, handed over = %d; want a partial drain", dropped, st.HandedOver)
	}
	if st.HandedOver+int64(dropped) != n {
		t.Errorf("handed over %d + dropped %d != %d accepted", st.HandedOver, dropped, n)
	}
	// What was delivered is a gapless prefix, in order.
	got := splitLines(c.received())
	if int64(len(got)) < st.HandedOver || int64(len(got)) > st.HandedOver+1 {
		t.Errorf("receiver has %d lines, stats say %d", len(got), st.HandedOver)
	}
	for i, line := range got {
		if !bytes.Equal(line, makeLine(fmt.Sprintf("e%03d", i), 100)) {
			t.Fatalf("line %d is out of order or damaged", i)
		}
	}
}

func TestShutdownCalledConcurrentlyReturnsOneAnswer(t *testing.T) {
	tg := newHangingTCP(t, 100)
	tg.remote.Enqueue("first", makeLine("first", 100))
	tg.blocked()
	for i := 0; i < 4; i++ {
		tg.remote.Enqueue(fmt.Sprint(i), makeLine("q", 100))
	}
	results := make([]int, 5)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			results[i] = tg.remote.Shutdown(ctx)
		}()
	}
	wg.Wait()
	for i, got := range results {
		if got != 5 {
			t.Errorf("caller %d got %d, want 5", i, got)
		}
	}
	assertNoLeaks(t)
}

func TestShutdownWithNilContextDrains(t *testing.T) {
	sink := newTCPSink(t, nil, nil)
	r := newTCP(t, TCPOptions{Address: sink.Addr()})
	r.Enqueue("e", makeLine("e", 100))
	// A nil context is tolerated and means "no deadline".
	if dropped := r.Shutdown(nil); dropped != 0 {
		t.Fatalf("dropped = %d", dropped)
	}
	if r.Stats().HandedOver != 1 {
		t.Error("event not delivered")
	}
}

// Every accepted event ends up delivered, failed or reported as dropped by
// Shutdown, and every rejected one is counted exactly once, even while
// producers race with Shutdown.
func TestEnqueueRacingShutdownKeepsTheBooks(t *testing.T) {
	slow := func() *fakeConn {
		c := newFakeConn()
		c.writeFn = func(c *fakeConn, p []byte) (int, error) {
			time.Sleep(50 * time.Microsecond)
			if c.isClosed() {
				return 0, net.ErrClosed
			}
			return len(p), nil
		}
		return c
	}
	slowRT := rtFunc(func(req *http.Request) (*http.Response, error) {
		time.Sleep(50 * time.Microsecond)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(nil)), Request: req}, nil
	})
	makers := map[string]func(t *testing.T) Remote{
		"tcp": func(t *testing.T) Remote {
			dial := func(context.Context, string, string) (net.Conn, error) { return slow(), nil }
			return newTCP(t, TCPOptions{Address: "collector.example.test:9000", QueueSize: 64, Hooks: Hooks{Dial: dial}})
		},
		"udp": func(t *testing.T) Remote {
			dial := func(context.Context, string, string) (net.Conn, error) { return slow(), nil }
			return newUDP(t, UDPOptions{Address: "collector.example.test:9001", QueueSize: 64, Hooks: Hooks{Dial: dial}})
		},
		"webhook": func(t *testing.T) Remote {
			return newWebhook(t, WebhookOptions{URL: "http://collector.example.test/hook", QueueSize: 64, Hooks: Hooks{Transport: slowRT}})
		},
	}
	for name, mk := range makers {
		t.Run(name, func(t *testing.T) {
			r := mk(t)
			var accepted, rejected atomic.Int64
			stop := make(chan struct{})
			var wg sync.WaitGroup
			for p := 0; p < 4; p++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					line := makeLine("race", 120)
					for {
						select {
						case <-stop:
							return
						default:
						}
						if r.Enqueue("race", line) {
							accepted.Add(1)
						} else {
							rejected.Add(1)
						}
					}
				}()
			}
			time.Sleep(40 * time.Millisecond)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			dropped := int64(r.Shutdown(ctx))
			time.Sleep(10 * time.Millisecond) // producers keep offering after Shutdown
			close(stop)
			wg.Wait()

			st := r.Stats()
			if got := st.HandedOver + st.Failed + dropped; got != accepted.Load() {
				t.Errorf("handed over %d + failed %d + dropped %d = %d, but %d events were accepted",
					st.HandedOver, st.Failed, dropped, got, accepted.Load())
			}
			if got := st.DroppedQueueFull + (st.DroppedShutdown - dropped); got != rejected.Load() {
				t.Errorf("rejected %d events, but the counters say %d", rejected.Load(), got)
			}
			if st.QueueLen != 0 {
				t.Errorf("QueueLen = %d after Shutdown", st.QueueLen)
			}
			if accepted.Load() == 0 || st.DroppedQueueFull == 0 {
				t.Logf("race not exercised: accepted %d, queue-full drops %d", accepted.Load(), st.DroppedQueueFull)
			}
		})
	}
	assertNoLeaks(t)
}

// The leak detector must see a running output and stop seeing it after
// Shutdown, otherwise assertNoLeaks proves nothing.
func TestLeakDetectorSeesRunningOutputs(t *testing.T) {
	sink := newTCPSink(t, nil, nil)
	r := newTCP(t, TCPOptions{Address: sink.Addr()})
	r.Enqueue("e", makeLine("e", 100)) // also starts the connection watcher
	waitFor(t, "delivery", func() bool { return r.Stats().HandedOver == 1 })
	if len(leakedGoroutines()) == 0 {
		t.Fatal("a running output is invisible to the leak detector")
	}
	shutdownRemote(t, r)
	assertNoLeaks(t)
}

func TestRemoteNamesAndInitialStats(t *testing.T) {
	for _, tg := range newTargets(t, 7) {
		st := tg.remote.Stats()
		if st.QueueCap != 7 || st.QueueLen != 0 || st.HandedOver+st.Failed+st.Retries+st.DroppedQueueFull+st.DroppedTooLarge+st.DroppedShutdown != 0 || st.LastError != "" {
			t.Errorf("%s: initial stats = %+v", tg.name, st)
		}
		want := map[string]string{"tcp": "tcp", "tcp+tls": "tcp", "udp": "udp", "webhook": "webhook", "webhook+tls": "webhook"}[tg.name]
		if tg.remote.Name() != want {
			t.Errorf("%s: Name = %q, want %q", tg.name, tg.remote.Name(), want)
		}
	}
}
