package output

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func newUDP(t *testing.T, opts UDPOptions) *udpRemote {
	t.Helper()
	opts.Hooks = fast(opts.Hooks)
	r, err := NewUDP(opts)
	if err != nil {
		t.Fatalf("NewUDP: %v", err)
	}
	cleanupShutdown(t, r)
	return r.(*udpRemote)
}

func TestUDPSendsOneEventPerDatagram(t *testing.T) {
	sink := newUDPSink(t)
	r := newUDP(t, UDPOptions{Address: sink.Addr()})

	want := map[string]bool{}
	sizes := []int{60, 200, 1000, 4000, 8192} // the last one is exactly the default limit
	for i, size := range sizes {
		id := fmt.Sprintf("evt-%d", i)
		line := makeLine(id, size)
		if len(line) != size {
			t.Fatalf("test line has %d bytes, want %d", len(line), size)
		}
		want[string(line)] = true
		if !r.Enqueue(id, line) {
			t.Fatalf("event %d rejected", i)
		}
	}
	sink.waitPackets(t, len(sizes))
	for _, pkt := range sink.Packets() {
		if !want[string(pkt)] {
			t.Errorf("datagram of %d bytes matches no event (truncated or split?)", len(pkt))
		}
		if pkt[len(pkt)-1] != '\n' {
			t.Error("datagram lacks the trailing newline")
		}
		delete(want, string(pkt))
	}
	if len(want) != 0 {
		t.Errorf("%d events never arrived as a single datagram", len(want))
	}
	shutdownRemote(t, r) // all counters are final afterwards
	if st := r.Stats(); st.HandedOver != int64(len(sizes)) || st.Retries != 0 || r.Name() != "udp" {
		t.Errorf("stats = %+v", st)
	}
}

func TestUDPMaxBytesBoundary(t *testing.T) {
	sink := newUDPSink(t)
	r := newUDP(t, UDPOptions{Address: sink.Addr(), MaxBytes: 512})

	atLimit, over := makeLine("at-limit", 512), makeLine("over", 513)
	if !r.Enqueue("at-limit", atLimit) {
		t.Fatal("an event of exactly MaxBytes was rejected")
	}
	if r.Enqueue("over", over) {
		t.Fatal("an event above MaxBytes was accepted")
	}
	sink.waitPackets(t, 1)
	shutdownRemote(t, r)

	if pk := sink.Packets(); len(pk) != 1 || !bytes.Equal(pk[0], atLimit) {
		t.Fatalf("receiver got %d datagrams, want only the one at the limit", len(pk))
	}
	st := r.Stats()
	if st.DroppedTooLarge != 1 || st.HandedOver != 1 || st.Failed != 0 || st.DroppedQueueFull != 0 {
		t.Errorf("stats = %+v", st)
	}
}

// After a DNS or socket error the socket is closed and re-established on a
// later event with backoff; events in between are dropped and counted.
func TestUDPReconnectsWithBackoffAfterErrors(t *testing.T) {
	clk := newFakeClock()
	var mu sync.Mutex
	var dials int
	good := newFakeConn()
	broken := newFakeConn()
	broken.writeFn = func(*fakeConn, []byte) (int, error) { return 0, errors.New("network is unreachable (injected)") }
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		dials++
		switch dials {
		case 1:
			return nil, errors.New("no such host (injected)")
		case 2:
			return broken, nil
		}
		return good, nil
	}
	dialCount := func() int { mu.Lock(); defer mu.Unlock(); return dials }

	r := newUDP(t, UDPOptions{Address: "collector.example.test:9001", Hooks: Hooks{Dial: dial, Now: clk.Now}})
	// settle waits until the worker has dealt with n events in total.
	settle := func(n int64) {
		t.Helper()
		waitFor(t, fmt.Sprintf("%d events to be processed", n), func() bool {
			st := r.Stats()
			return st.HandedOver+st.Failed+st.DroppedTooLarge == n
		})
	}
	send := func(id string) []byte {
		line := makeLine(id, 100)
		if !r.Enqueue(id, line) {
			t.Fatalf("%s rejected", id)
		}
		return line
	}

	send("A") // DNS error
	settle(1)
	send("B") // inside the backoff window: dropped without dialing
	settle(2)
	if n := dialCount(); n != 1 {
		t.Fatalf("dials = %d during backoff, want 1", n)
	}

	clk.Advance(time.Second) // window over
	send("C")                // socket error: socket closed, new backoff
	settle(3)
	if !broken.isClosed() {
		t.Error("the failing socket was not closed")
	}
	send("D") // dropped again
	settle(4)
	if n := dialCount(); n != 2 {
		t.Fatalf("dials = %d, want 2", n)
	}

	clk.Advance(time.Second)
	e := send("E") // re-resolved, delivered
	settle(5)
	f := send("F") // same socket, no new dial
	settle(6)

	if n := dialCount(); n != 3 {
		t.Errorf("dials = %d, want 3", n)
	}
	if got := good.received(); !bytes.Equal(got, append(append([]byte{}, e...), f...)) {
		t.Errorf("good socket received %d bytes", len(got))
	}
	st := r.Stats()
	if st.HandedOver != 2 || st.Failed != 4 {
		t.Errorf("stats = %+v, want 2 delivered and 4 failed (2 errors + 2 dropped in backoff)", st)
	}
	if st.Retries != 0 {
		t.Errorf("Retries = %d, UDP never retransmits", st.Retries)
	}
}

func TestUDPBackoffGrowsWithConsecutiveFailures(t *testing.T) {
	clk := newFakeClock()
	var dials int
	var mu sync.Mutex
	dial := func(context.Context, string, string) (net.Conn, error) {
		mu.Lock()
		dials++
		mu.Unlock()
		return nil, errors.New("no such host (injected)")
	}
	// Production backoff (1s, 2s, 4s ... capped at 30s), no jitter.
	r, err := NewUDP(UDPOptions{Address: "collector.example.test:9001", Hooks: Hooks{Dial: dial, Now: clk.Now, BackoffJitter: -1}})
	must(t, err)
	cleanupShutdown(t, r)

	step := 0
	attempt := func() {
		step++
		r.Enqueue("e", makeLine("e", 100))
		waitFor(t, "event to be processed", func() bool { return r.Stats().Failed == int64(step) })
	}
	attempt() // failure 1 -> next dial allowed after 1s
	clk.Advance(999 * time.Millisecond)
	attempt() // still inside the window
	mu.Lock()
	d := dials
	mu.Unlock()
	if d != 1 {
		t.Fatalf("dials = %d, the first window must last 1s", d)
	}
	clk.Advance(time.Millisecond)
	attempt() // failure 2 -> window 2s
	clk.Advance(1999 * time.Millisecond)
	attempt()
	mu.Lock()
	d = dials
	mu.Unlock()
	if d != 2 {
		t.Fatalf("dials = %d, the second window must last 2s", d)
	}
}

func TestUDPMessageSizeErrorDropsOnlyThatEvent(t *testing.T) {
	c := newFakeConn()
	c.writeFn = func(*fakeConn, []byte) (int, error) {
		return 0, &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", syscall.EMSGSIZE)}
	}
	var mu sync.Mutex
	dials := 0
	dial := func(context.Context, string, string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		dials++
		return c, nil
	}
	r := newUDP(t, UDPOptions{Address: "collector.example.test:9001", Hooks: Hooks{Dial: dial}})
	r.Enqueue("big", makeLine("big", 200))
	waitFor(t, "oversize drop", func() bool { return r.Stats().DroppedTooLarge == 1 })
	if c.isClosed() {
		t.Fatal("socket closed for a single oversize datagram")
	}

	c.mu.Lock()
	c.writeFn = nil
	c.mu.Unlock()
	r.Enqueue("ok", makeLine("ok", 100))
	waitFor(t, "next event", func() bool { return r.Stats().HandedOver == 1 })
	mu.Lock()
	defer mu.Unlock()
	if dials != 1 {
		t.Errorf("dials = %d, want the same socket to continue", dials)
	}
	if st := r.Stats(); st.Failed != 0 {
		t.Errorf("Failed = %d, an oversize datagram is not a transport failure", st.Failed)
	}
}

func TestNewUDPValidation(t *testing.T) {
	bad := []struct {
		name string
		opts UDPOptions
	}{
		{"empty address", UDPOptions{}},
		{"no port", UDPOptions{Address: "192.0.2.20"}},
		{"max bytes negative", UDPOptions{Address: "192.0.2.20:9001", MaxBytes: -1}},
		{"max bytes above the UDP limit", UDPOptions{Address: "192.0.2.20:9001", MaxBytes: 65508}},
		{"negative queue", UDPOptions{Address: "192.0.2.20:9001", QueueSize: -5}},
		{"negative write timeout", UDPOptions{Address: "192.0.2.20:9001", WriteTimeout: -1}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if r, err := NewUDP(tc.opts); err == nil {
				r.Shutdown(context.Background())
				t.Fatal("NewUDP succeeded")
			}
		})
	}
	r, err := NewUDP(UDPOptions{Address: "[2001:db8::20]:9001", MaxBytes: 65507})
	must(t, err)
	shutdownRemote(t, r)
	r, err = NewUDP(UDPOptions{Address: "192.0.2.20:9001"})
	must(t, err)
	if r.(*udpRemote).maxBytes != 8192 || r.Stats().QueueCap != 10000 {
		t.Error("defaults are not MaxBytes 8192 and QueueSize 10000")
	}
	shutdownRemote(t, r)
}
