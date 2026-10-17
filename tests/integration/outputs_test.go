//go:build linux

package integration

// End to end scenarios of the local log and the remote outputs (TCP, UDP,
// webhook): what the receivers get, how failures are contained, the exclusion
// scopes, TLS, size limits, shutdown behaviour and the safety of the log file.
// the output requirements and internal/output/DELIVERY.md define
// the behaviour that is asserted. The receivers and helpers are in
// outputs_helper_test.go.

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// outProcessEvents returns the events of the process lifecycle (no agent events).
func outProcessEvents(evs []Ev) []Ev {
	return filterEv(evs, func(e Ev) bool { return strings.HasPrefix(e.Type(), "process.") })
}

// outCheckSequence asserts that the sequence of the log lines is strictly
// increasing, and, with contiguous set, that it has no gap.
func outCheckSequence(t *testing.T, evs []Ev, contiguous bool) {
	t.Helper()
	prev := 0
	for i, e := range evs {
		switch {
		case e.Seq() <= prev:
			t.Fatalf("sequence is not strictly increasing: line %d has %d after %d", i+1, e.Seq(), prev)
		case contiguous && i > 0 && e.Seq() != prev+1:
			t.Fatalf("sequence has a gap: line %d has %d after %d", i+1, e.Seq(), prev)
		}
		prev = e.Seq()
	}
}

// outStopAndEvents stops the agent with SIGTERM, requires exit code 0 within
// shutdown_timeout plus a few seconds and agent.stopped as the last line of the
// log, and returns the events of the log.
func outStopAndEvents(t *testing.T, a *agent) []Ev {
	t.Helper()
	start := time.Now()
	code := a.Stop()
	took := time.Since(start)
	if code != 0 {
		t.Fatalf("the agent ended with exit code %d, want 0:\n%s", code, a.stderr.String())
	}
	// The orderly shutdown is bounded by runtime.shutdown_timeout (the shutdown requirements).
	if v, ok := outShutdownLimit.Load(a); ok && took > v.(time.Duration)+5*time.Second {
		t.Errorf("the agent needed %s to stop, its shutdown_timeout is %s", took, v)
	}
	evs := a.Events()
	if n := len(evs); n == 0 || evs[n-1].Type() != "agent.stopped" {
		t.Fatalf("the last line of the log is not agent.stopped:\n%s", summarize(evs, 10))
	}
	return evs
}

// ----------------------------------------------------------------------------
// 1. All outputs carry the same bytes

func TestOutAllOutputsIdentical(t *testing.T) {
	requireRoot(t)
	tcp := outNewTCPServer(t, outTCPOpts{})
	udp := outNewUDPServer(t)
	hook := outNewHookServer(t)
	d := newProgDir(t)
	tk := outNewToken()
	a := outStart(t, outCfg{
		Token:       tk,
		CaptureArgv: true, TCP: tcp.Addr, UDP: udp.Addr, Webhook: hook.URL + "/events", Health: "500ms",
	})

	const children = 150
	root := d.outBurst(tk.Root(), children, 0, 2)
	pids := outBurstDone(t, root, 10*time.Minute)
	if len(pids) != children {
		t.Fatalf("the helper reported %d children, want %d", len(pids), children)
	}
	outWaitAfterExit(t, a, root.PID, 60*time.Second)
	// Arguments with a newline, a quote and invalid UTF-8 must stay one line on
	// every output, also in the newline separated TCP stream.
	special := d.start(tk.Name("special"), "args-special")
	special.waitLine("child ", 60*time.Second)
	outWaitAfterExit(t, a, special.PID, 60*time.Second)
	evs := outStopAndEvents(t, a)
	outCheckSequence(t, evs, false)
	byID := outByID(evs)
	want := outRemoteEvents(evs)
	stopped := evs[len(evs)-1]
	version := ofType(evs, "agent.started")[0].str("details.version")
	t.Logf("%d events in the log, %d offered to each remote output", len(evs), len(want))
	if n := len(filterEv(ofType(evs, "process.exec"), func(e Ev) bool {
		args := e.argv()
		return len(args) == 5 && args[1] == "line1\nline2"
	})); n != 1 {
		t.Fatalf("%d exec events with the special arguments in the log, want 1", n)
	}

	// Every process of the burst is in the log with its complete lifecycle.
	for _, pid := range pids {
		if got := kinds(ofPID(evs, pid)); got != "fork,exec,exit" {
			t.Fatalf("child %d: log records [%s], want fork,exec,exit", pid, got)
		}
	}

	// TCP: a newline separated stream on one connection, in log order.
	outWait(t, 30*time.Second, "the TCP connection to be closed", func() bool { return tcp.NumConns() > 0 && tcp.AllEnded() })
	if n := tcp.NumConns(); n != 1 {
		t.Errorf("the agent used %d TCP connections, want 1 (persistent connection)", n)
	}
	tcpLines := tcp.LineBytes()
	tcpCount := outAssertIdentical(t, "tcp", tcpLines, byID)
	if miss := outMissing(want, tcpCount); len(miss) > 0 {
		t.Errorf("tcp is missing %d events, e.g. %v", len(miss), miss[:min(3, len(miss))])
	}
	var tcpIDs []string
	for _, l := range tcpLines {
		tcpIDs = append(tcpIDs, outEventID(l))
	}
	if got, exp := strings.Join(tcpIDs, ","), strings.Join(outIDs(want), ","); got != exp {
		t.Errorf("tcp delivered the events in a different order or with duplicates (%d received, %d expected)", len(tcpIDs), len(want))
	}
	if tail := tcp.Conns()[0].Tail; len(tail) != 0 {
		t.Errorf("tcp stream ends in an unterminated line: %q", outClip(tail))
	}

	// Webhook: one request per event, body = the line, headers as specified.
	acc := hook.Accepted()
	if len(acc) != len(want) {
		t.Errorf("webhook: %d accepted requests, want %d", len(acc), len(want))
	}
	var hookBodies [][]byte
	var hookIDs []string
	for _, r := range acc {
		hookBodies = append(hookBodies, r.Body)
		id := outEventID(r.Body)
		hookIDs = append(hookIDs, id)
		if r.Method != "POST" {
			t.Errorf("webhook request %d: method %s", r.N, r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-ndjson" {
			t.Errorf("webhook request %d: Content-Type %q", r.N, got)
		}
		if got := r.Header.Get("User-Agent"); got != "process-watcher/"+version {
			t.Errorf("webhook request %d: User-Agent %q, want process-watcher/%s", r.N, got, version)
		}
		if got := r.Header.Get("X-Event-ID"); got != id {
			t.Errorf("webhook request %d: X-Event-ID %q, body has event_id %q", r.N, got, id)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("webhook request %d: Authorization %q without token_env", r.N, got)
		}
		if r.Length != int64(len(r.Body)) || len(r.Encoding) != 0 {
			t.Errorf("webhook request %d: Content-Length %d for a body of %d bytes, Transfer-Encoding %v: the body must be sent with a length", r.N, r.Length, len(r.Body), r.Encoding)
		}
		if r.Path != "/events" {
			t.Errorf("webhook request %d: path %q", r.N, r.Path)
		}
	}
	hookCount := outAssertIdentical(t, "webhook", hookBodies, byID)
	if miss := outMissing(want, hookCount); len(miss) > 0 {
		t.Errorf("webhook is missing %d events, e.g. %v", len(miss), miss[:min(3, len(miss))])
	}
	if got, exp := strings.Join(hookIDs, ","), strings.Join(outIDs(want), ","); got != exp {
		t.Errorf("webhook delivered the events in a different order or with duplicates")
	}

	// UDP: one datagram per event. Loopback may lose datagrams under load, so
	// the agent's own counter is the reference for what was handed over.
	handed := outOutput(stopped, "udp", "handed_over")
	outWaitDatagrams(udp, handed, 20*time.Second)
	udpCount := outAssertIdentical(t, "udp", udp.Datagrams(), byID)
	lost := 0
	for _, e := range want {
		switch udpCount[e.str("event_id")] {
		case 0:
			lost++
		case 1:
		default:
			t.Errorf("udp: event %s arrived %d times", e.str("event_id"), udpCount[e.str("event_id")])
		}
	}
	t.Logf("udp: %d of %d events received (agent handed over %d, dropped_queue_full %d), tcp %d, webhook %d",
		len(want)-lost, len(want), handed, outOutput(stopped, "udp", "dropped_queue_full"), len(tcpLines), len(acc))
	if lost > len(want)/20 {
		t.Errorf("udp lost %d of %d datagrams on loopback", lost, len(want))
	}

	// The counters of the agent agree with what happened.
	for _, name := range []string{"tcp", "udp", "webhook"} {
		if got := outOutput(stopped, name, "handed_over"); got != len(want) {
			t.Errorf("%s: handed_over %d, want %d", name, got, len(want))
		}
		for _, k := range []string{"failed", "dropped_queue_full", "dropped_too_large", "dropped_shutdown", "retries"} {
			if got := outOutput(stopped, name, k); got != 0 {
				t.Errorf("%s: %s %d, want 0", name, k, got)
			}
		}
	}
	if got := outCount(stopped, "details.undelivered_at_shutdown.tcp") + outCount(stopped, "details.undelivered_at_shutdown.udp") +
		outCount(stopped, "details.undelivered_at_shutdown.webhook"); got != 0 {
		t.Errorf("undelivered at shutdown: %d, want 0", got)
	}
	if lines := outOutput(stopped, "file", "lines"); lines != len(evs)-1 {
		t.Errorf("file output counted %d lines, the log has %d before agent.stopped", lines, len(evs)-1)
	}
}

// ----------------------------------------------------------------------------
// 2. Exclusions: scope remote keeps them in the file, scope all drops them

func TestOutExclusions(t *testing.T) {
	requireRoot(t)
	t.Run("default scope remote", func(t *testing.T) { outExclusionScenario(t, "", true) })
	t.Run("scope all", func(t *testing.T) { outExclusionScenario(t, "all", true) })
	// suppressed_outputs lists the outputs that are enabled, not all three.
	t.Run("scope remote with tcp disabled", func(t *testing.T) { outExclusionScenario(t, "remote", false) })
}

func outExclusionScenario(t *testing.T, scope string, withTCP bool) {
	udp := outNewUDPServer(t)
	hook := outNewHookServer(t)
	tcpAddr := ""
	var tcp *outTCPServer
	wantSuppressed := []string{"udp", "webhook"}
	if withTCP {
		tcp = outNewTCPServer(t, outTCPOpts{})
		tcpAddr = tcp.Addr
		wantSuppressed = []string{"tcp", "udp", "webhook"}
	}
	d := newProgDir(t)
	tk := outNewToken()
	// Besides the excluded helper the list has words that occur in the agent's
	// own events: agent events must never be touched by process exclusions.
	exclude := []string{tk.Name("secret"), "agent", "health", "ready", "started", "stopped", "process-watcher"}
	a := outStart(t, outCfg{
		Token: tk, ExcludeImage: exclude, ExcludeScope: scope, TCP: tcpAddr, UDP: udp.Addr, Webhook: hook.URL, Health: "500ms",
	})

	// root -> plain (visible) and root -> secret (excluded) -> shell (visible).
	// The fork of the shell inherits the image of its creator, so that event is
	// excluded too; the shell's exec and exit are not (the exclusion is
	// evaluated per event and never inherited).
	tree := d.startNode(recipe{Name: tk.Root(), Children: []recipe{
		{Name: tk.Name("plain"), Mode: "sleep", Args: []string{"150"}},
		{Name: tk.Name("secret"), Children: []recipe{
			{Name: tk.Name("shell"), Mode: "sleep", Args: []string{"150"}},
		}},
	}})
	tree.wait(30 * time.Second)
	outWaitAfterExit(t, a, tree.PID, 30*time.Second)
	evs := outStopAndEvents(t, a)
	stopped := evs[len(evs)-1]
	byID := outByID(evs)

	// The events the exclusion applies to: those whose own image contains the string.
	isSecret := func(e Ev) bool { return strings.Contains(e.Image(), tk.Name("secret")) }
	secret := filterEv(outProcessEvents(evs), isSecret)
	excluded := filterEv(outProcessEvents(evs), func(e Ev) bool { return e.get("filter.excluded") == true })

	// agent.health carries the exclusion counters; the last one comes after the tree ended.
	health := ofType(evs, "agent.health")
	lastHealth := health[len(health)-1]
	details := func(e Ev) string { return outClip([]byte(e.Line[strings.Index(e.Line, `"details"`):])) }

	if scope == "all" {
		// Suppressed everywhere, also in the file; the counters and the gaps in the sequence show it.
		if len(secret) != 0 || len(excluded) != 0 {
			t.Errorf("scope all: the log has %d events of the excluded image and %d flagged as excluded", len(secret), len(excluded))
		}
		outCheckSequence(t, evs, false)
		gaps := stopped.Seq() - len(evs)
		got := outCount(lastHealth, "details.filter.excluded_all")
		if gaps < 3 || got != gaps {
			t.Errorf("scope all: %d sequence numbers are missing, the last agent.health counts %d excluded events (want equal, and at least 3: exec, exit and the shell's inherited fork)", gaps, got)
		}
		if got := outCount(lastHealth, "details.filter.excluded_remote"); got != 0 {
			t.Errorf("scope all: excluded_remote %d, want 0", got)
		}
		// agent.stopped is the record of the final counters (the requirements ask for the final counters at shutdown).
		if got := outCount(stopped, "details.filter.excluded_all"); got != gaps {
			t.Errorf("scope all: agent.stopped has details.filter.excluded_all=%d, want %d; its details: %s", got, gaps, details(stopped))
		}
	} else {
		outCheckSequence(t, evs, true)
		if len(secret) < 3 {
			t.Fatalf("the log has only %d events of the image %s (exec, exit and the shell's fork expected):\n%s", len(secret), tk.Name("secret"), summarize(outProcessEvents(evs), 40))
		}
		if got, exp := strings.Join(outIDs(excluded), ","), strings.Join(outIDs(secret), ","); got != exp {
			t.Errorf("excluded events %v differ from the events of the excluded image %v", outIDs(excluded), outIDs(secret))
		}
		for _, e := range outProcessEvents(evs) {
			matches, mok := e.get("filter.matches").([]any)
			sup, sok := e.get("filter.suppressed_outputs").([]any)
			if !mok || !sok {
				t.Errorf("%s #%d: filter.matches and filter.suppressed_outputs must be arrays: %v", e.Type(), e.Seq(), e.get("filter"))
				continue
			}
			if e.get("filter.excluded") != true {
				if len(matches) != 0 || len(sup) != 0 {
					t.Errorf("%s #%d is not excluded but has matches %v and suppressed outputs %v", e.Type(), e.Seq(), matches, sup)
				}
				continue
			}
			if len(matches) != 1 {
				t.Errorf("excluded %s #%d: %d matches, want 1", e.Type(), e.Seq(), len(matches))
			} else if mm, _ := matches[0].(map[string]any); mm["field"] != "image" || mm["value"] != tk.Name("secret") {
				t.Errorf("excluded %s #%d: match %v, want field image and the configured string %s", e.Type(), e.Seq(), matches[0], tk.Name("secret"))
			}
			var names []string
			for _, o := range sup {
				names = append(names, fmt.Sprint(o))
			}
			if got := strings.Join(names, ","); got != strings.Join(wantSuppressed, ",") {
				t.Errorf("excluded %s #%d: suppressed_outputs %v, want the enabled outputs %v", e.Type(), e.Seq(), names, wantSuppressed)
			}
		}
		// The shell's fork carries the excluded image, the shell itself does not.
		kindList := map[string]bool{}
		for _, e := range secret {
			kindList[strings.TrimPrefix(e.Type(), "process.")] = true
		}
		if !kindList["exec"] || !kindList["exit"] || !kindList["fork"] {
			t.Errorf("excluded events by kind: %v, want exec, exit and fork", kindList)
		}
		for _, name := range []string{tk.Name("shell"), tk.Name("plain")} {
			for _, typ := range []string{"process.exec", "process.exit"} {
				n := len(filterEv(ofType(evs, typ), func(e Ev) bool { return e.Image() == name && e.get("filter.excluded") == false }))
				if n != 1 {
					t.Errorf("%s: %d visible %s events, want 1 (an excluded parent does not hide its children)", name, n, typ)
				}
			}
		}
		if got := outCount(lastHealth, "details.filter.excluded_remote"); got != len(secret) {
			t.Errorf("the last agent.health counts %d events excluded for the remote outputs, the log has %d", got, len(secret))
		}
		if got := outCount(lastHealth, "details.filter.excluded_all"); got != 0 {
			t.Errorf("excluded_all %d, want 0", got)
		}
		if got := outCount(stopped, "details.filter.excluded_remote"); got != len(secret) {
			t.Errorf("agent.stopped has details.filter.excluded_remote=%d, want %d; its details: %s", got, len(secret), details(stopped))
		}
	}

	// Agent events are never excluded.
	for _, e := range evs {
		if strings.HasPrefix(e.Type(), "agent.") && e.get("filter.excluded") != false {
			t.Errorf("%s #%d: filter.excluded %v", e.Type(), e.Seq(), e.get("filter.excluded"))
		}
	}

	// The remote outputs get everything except the excluded events (and agent.stopped).
	want := outRemoteEvents(evs)
	received := map[string][][]byte{}
	if withTCP {
		outWait(t, 30*time.Second, "the TCP connection to be closed", func() bool { return tcp.NumConns() > 0 && tcp.AllEnded() })
		received["tcp"] = tcp.LineBytes()
	}
	outWaitDatagrams(udp, outOutput(stopped, "udp", "handed_over"), 20*time.Second)
	received["udp"] = udp.Datagrams()
	for _, r := range hook.Accepted() {
		received["webhook"] = append(received["webhook"], r.Body)
	}
	for name, got := range received {
		count := outAssertIdentical(t, name, got, byID)
		for id := range count {
			if e := byID[id]; e.get("filter.excluded") == true || isSecret(e) {
				t.Errorf("%s received the excluded event %s %s", name, e.Type(), id)
			}
		}
		lost := len(outMissing(want, count))
		if name == "udp" {
			if lost > len(want)/20 {
				t.Errorf("udp did not receive %d of %d events", lost, len(want))
			}
		} else if lost > 0 {
			t.Errorf("%s did not receive %d events, e.g. %v", name, lost, outMissing(want, count)[:min(3, lost)])
		}
		agentEvents := 0
		for id := range count {
			if strings.HasPrefix(byID[id].Type(), "agent.") {
				agentEvents++
			}
		}
		if agentEvents < 3 {
			t.Errorf("%s received %d agent events (started, ready, health expected)", name, agentEvents)
		}
	}
	if !withTCP && outOutput(stopped, "tcp", "handed_over") != 0 {
		t.Errorf("a disabled output has counters: %v", stopped.get("details.outputs"))
	}
}

// ----------------------------------------------------------------------------
// 3. A hanging or unreachable TCP target does not disturb the file or the other outputs

func TestOutHangingTCPTarget(t *testing.T) {
	requireRoot(t)

	t.Run("target accepts but never reads", func(t *testing.T) {
		// The receive buffer of the listener is tiny, so the connection stalls
		// as soon as the agent's own send buffer is full.
		tcp := outNewTCPServer(t, outTCPOpts{RcvBuf: 2048, Policy: func(int) outConnPolicy { return outConnPolicy{Hang: true} }})
		udp := outNewUDPServer(t)
		d := newProgDir(t)
		tk := outNewToken()
		const queue = 50
		a := outStart(t, outCfg{
			Token:       tk,
			CaptureArgv: true, TCP: tcp.Addr, UDP: udp.Addr, QueueSize: queue, Health: "200ms",
			WriteTO: "1s", ConnectTO: "2s", MaxRetries: outInt(2), Shutdown: "3s",
			RingMB: 64, // a burst of this size must not lose records even if another suite loads the machine
		})

		// About 9 MB in 2400 events, several times what the socket buffers hold
		// and far more events than the queues of 50.
		const children = 800
		root := d.outBurst(tk.Root(), children, 3500, 4)
		pids := outBurstDone(t, root, 10*time.Minute)
		if len(pids) != children {
			t.Fatalf("the helper reported %d children, want %d", len(pids), children)
		}
		evs := outWaitAfterExit(t, a, root.PID, 120*time.Second)
		fileEvents := len(evs)

		// The UDP output kept receiving while the TCP connection was stuck.
		outWait(t, 60*time.Second, "UDP to receive at least half of the events while tcp is stuck", func() bool {
			return udp.Count() >= fileEvents/2
		})
		if n := tcp.NumConns(); n < 1 {
			t.Fatal("the TCP target was never contacted")
		}

		evs = outStopAndEvents(t, a)
		stopped := evs[len(evs)-1]
		byID := outByID(evs)

		// The local file is complete: no gap in the sequence, every child has its lifecycle.
		outCheckSequence(t, evs, true)
		for _, pid := range pids {
			if got := kinds(ofPID(evs, pid)); got != "fork,exec,exit" {
				t.Fatalf("child %d: log records [%s], want fork,exec,exit", pid, got)
			}
		}
		if lost := stopped.num("details.collector.lost_total"); lost != 0 {
			t.Fatalf("the collector lost %d records; the file cannot be complete", lost)
		}

		// The queues stay bounded.
		maxLen := 0
		for _, h := range ofType(evs, "agent.health") {
			for _, name := range []string{"tcp", "udp"} {
				if q := outOutput(h, name, "queue_len"); q > queue {
					t.Errorf("health #%d: %s queue_len %d exceeds queue_size %d", h.Seq(), name, q, queue)
				} else if name == "tcp" {
					maxLen = max(maxLen, q)
				}
			}
		}
		if maxLen == 0 {
			t.Error("the tcp queue was never seen with entries although the target does not read")
		}

		// Events that did not fit were dropped for tcp and counted.
		dropped := outOutput(stopped, "tcp", "dropped_queue_full")
		if dropped == 0 {
			t.Errorf("tcp: dropped_queue_full is 0 although %d events were offered to a stuck target with a queue of %d", len(outRemoteEvents(evs)), queue)
		}
		healthDropped := 0
		for _, h := range ofType(evs, "agent.health") {
			healthDropped = max(healthDropped, outOutput(h, "tcp", "dropped_queue_full"))
		}
		if healthDropped == 0 {
			t.Error("no agent.health event reports dropped_queue_full for the stuck tcp output")
		}
		offered := len(outRemoteEvents(evs))
		undelivered := outCount(stopped, "details.undelivered_at_shutdown.tcp")
		if undelivered > queue+1 {
			t.Errorf("tcp: %d events undelivered at shutdown, more than queue_size+1 = %d", undelivered, queue+1)
		}
		if sum := outOutput(stopped, "tcp", "handed_over") + outOutput(stopped, "tcp", "failed") + dropped + undelivered; sum != offered {
			t.Errorf("tcp: handed_over %d + failed %d + dropped_queue_full %d + undelivered %d = %d, but %d events were offered",
				outOutput(stopped, "tcp", "handed_over"), outOutput(stopped, "tcp", "failed"), dropped, undelivered, sum, offered)
		}

		// UDP got its events; the agent's counters say what it handed over.
		handed := outOutput(stopped, "udp", "handed_over")
		outWaitDatagrams(udp, handed, 20*time.Second)
		count := outAssertIdentical(t, "udp", udp.Datagrams(), byID)
		t.Logf("%d events in the log; tcp: handed over %d, dropped (queue full) %d, failed %d, retries %d, undelivered %d, %d connection(s); udp: handed over %d, dropped %d, received %d",
			offered, outOutput(stopped, "tcp", "handed_over"), dropped, outOutput(stopped, "tcp", "failed"), outOutput(stopped, "tcp", "retries"),
			undelivered, tcp.NumConns(), handed, outOutput(stopped, "udp", "dropped_queue_full"), len(count))
		if len(count) < offered/2 {
			t.Errorf("udp received %d of %d events although only tcp was stuck", len(count), offered)
		}
	})

	t.Run("target unreachable", func(t *testing.T) {
		closed := outClosedAddr(t)
		udp := outNewUDPServer(t)
		d := newProgDir(t)
		tk := outNewToken()
		a := outStart(t, outCfg{
			Token: tk,
			TCP:   closed, UDP: udp.Addr, QueueSize: 50, Health: "300ms",
			MaxRetries: outInt(2), ConnectTO: "1s", WriteTO: "1s", Shutdown: "2s",
		})
		// After its retries (three attempts) the first event is counted as failed.
		evs := outWaitHealth(t, a, 60*time.Second, "a health event with failed tcp events", func(h Ev) bool {
			return outOutput(h, "tcp", "failed") >= 1
		})
		var h Ev
		for _, e := range ofType(evs, "agent.health") {
			if outOutput(e, "tcp", "failed") >= 1 {
				h = e
				break
			}
		}
		if got := outOutput(h, "tcp", "retries"); got < 2 {
			t.Errorf("the first failed event used %d retries, want 2 (max_retries)", got)
		}
		if got := outOutput(h, "tcp", "handed_over"); got != 0 {
			t.Errorf("tcp handed_over %d for an unreachable target", got)
		}
		select {
		case <-a.done:
			t.Fatalf("the agent exited (%d) because a remote target is unreachable:\n%s", a.exit, a.stderr.String())
		default:
		}
		if !strings.Contains(a.stderr.String(), "connection refused") {
			t.Errorf("stderr does not say why the delivery failed:\n%s", a.stderr.String())
		}

		// The agent keeps observing and writing the file, and the other outputs work.
		root := d.outBurst(tk.Root(), 60, 0, 1)
		pids := outBurstDone(t, root, 10*time.Minute)
		evs = a.waitEvents(60*time.Second, "the root's exit", func(evs []Ev) bool {
			return len(filterEv(ofType(evs, "process.exit"), func(e Ev) bool { return e.PID() == root.PID })) > 0
		})
		for _, pid := range pids {
			if got := kinds(ofPID(evs, pid)); got != "fork,exec,exit" {
				t.Fatalf("child %d: log records [%s], want fork,exec,exit", pid, got)
			}
		}
		evs = outStopAndEvents(t, a)
		outCheckSequence(t, evs, true)
		stopped := evs[len(evs)-1]
		handed := outOutput(stopped, "udp", "handed_over")
		outWaitDatagrams(udp, handed, 20*time.Second)
		count := outAssertIdentical(t, "udp", udp.Datagrams(), outByID(evs))
		if want := outRemoteEvents(evs); len(count) < len(want)*9/10 {
			t.Errorf("udp received %d of %d events", len(count), len(want))
		}
		if outOutput(stopped, "tcp", "failed") < 1 || outOutput(stopped, "tcp", "handed_over") != 0 {
			t.Errorf("tcp counters in agent.stopped: %v", stopped.get("details.outputs.tcp"))
		}
		// Transport errors are aggregated: no flood of log lines, and no events about them.
		if n := strings.Count(a.stderr.String(), "remote delivery"); n > 2 {
			t.Errorf("%d delivery error lines on stderr within seconds, want the first error and at most one summary:\n%s", n, a.stderr.String())
		}
		for _, e := range evs {
			if typ := e.Type(); !strings.HasPrefix(typ, "process.") && typ != "agent.started" && typ != "agent.ready" && typ != "agent.health" && typ != "agent.stopped" {
				t.Errorf("unexpected %s event #%d: delivery errors must not turn into events", typ, e.Seq())
			}
		}
	})
}

// ----------------------------------------------------------------------------
// 4. TCP: reconnect after the receiver closed the connection or after a partial write

func TestOutTCPReconnect(t *testing.T) {
	requireRoot(t)

	// The receiver closes connections: cleanly after a few lines, in the
	// middle of a line (the rest of that line is discarded, so the kernel
	// answers with a reset) and once more cleanly. Events come at the pace of
	// the health interval, so the agent has long noticed each closed
	// connection (it reads from it to learn about FIN and RST) when the next
	// event is due, and replaces the connection before it writes.
	t.Run("receiver closes connections", func(t *testing.T) {
		const cutBytes = 100
		srv := outNewTCPServer(t, outTCPOpts{Policy: func(i int) outConnPolicy {
			switch i {
			case 0:
				return outConnPolicy{CloseAfterLines: 3}
			case 1:
				return outConnPolicy{CutAfterLines: 2, CutBytes: cutBytes}
			case 2:
				return outConnPolicy{CloseAfterLines: 1}
			}
			return outConnPolicy{}
		}})
		tk := outNewToken()
		a := outStart(t, outCfg{Token: tk, TCP: srv.Addr, Health: "600ms", ConnectTO: "2s", WriteTO: "2s"})
		outWait(t, 60*time.Second, "four connections and lines on the fourth", func() bool {
			c := srv.Conns()
			return len(c) >= 4 && len(c[3].Lines) >= 2
		})
		evs := outStopAndEvents(t, a)
		byID := outByID(evs)
		want := outRemoteEvents(evs)
		outWait(t, 30*time.Second, "all connections to end", srv.AllEnded)
		conns := srv.Conns()

		// Behaviour of the receiver, as scripted.
		if len(conns[0].Lines) != 3 || len(conns[0].Tail) != 0 || conns[0].EndedBy != "server" {
			t.Errorf("connection 0: %d lines, tail %d bytes, ended by %s", len(conns[0].Lines), len(conns[0].Tail), conns[0].EndedBy)
		}
		if len(conns[1].Lines) != 2 || len(conns[1].Tail) != cutBytes || conns[1].EndedBy != "server" {
			t.Fatalf("connection 1: %d lines, tail %d bytes, ended by %s; want 2 lines and a tail of %d bytes", len(conns[1].Lines), len(conns[1].Tail), conns[1].EndedBy, cutBytes)
		}
		if len(conns[2].Lines) != 1 {
			t.Errorf("connection 2: %d lines, want 1", len(conns[2].Lines))
		}

		// Everything that arrived complete is byte-identical to the log line.
		got := outAssertIdentical(t, "tcp", srv.LineBytes(), byID)

		// The unterminated fragment on the connection that was cut is the start
		// of exactly one log line: the event the receiver cut off. The sender
		// had handed that event over successfully, so it is not repeated: TCP
		// gives no acknowledgement, which DELIVERY.md and the UDP requirements
		// state. Every other event arrived, on the new connections.
		tail := string(conns[1].Tail)
		var cut []string
		for _, e := range want {
			if strings.HasPrefix(e.Line+"\n", tail) {
				cut = append(cut, e.str("event_id"))
			}
		}
		if len(cut) != 1 {
			t.Fatalf("the %d byte fragment is the start of %d log lines, want exactly 1", len(tail), len(cut))
		}
		miss := outMissing(want, got)
		if len(miss) != 1 || !strings.HasPrefix(miss[0], cut[0]) {
			t.Errorf("events that never arrived complete: %v; expected only the cut event %s", miss, cut[0])
		}
		for id, n := range got {
			if n > 1 {
				t.Errorf("event %s arrived %d times on healthy connections", id, n)
			}
		}
		t.Logf("%d connections; the receiver cut %s (%s); %d of %d events arrived complete", len(conns), cut[0], byID[cut[0]].Type(), len(got), len(want))
	})

	// The receiver stops reading, so the write of one line stalls half way
	// and fails with a timeout: the agent drops the connection, connects again
	// and sends the WHOLE event again, as the first line of the new connection.
	// The old connection still ends in the fragment of that line (the receiver
	// reads it later); every other event is complete on exactly one connection.
	t.Run("partial write times out", func(t *testing.T) {
		srv := outNewTCPServer(t, outTCPOpts{RcvBuf: 2048, Policy: func(i int) outConnPolicy { return outConnPolicy{Hang: i == 0} }})
		d := newProgDir(t)
		tk := outNewToken()
		a := outStart(t, outCfg{
			Token:       tk,
			CaptureArgv: true, TCP: srv.Addr, WriteTO: "1s", ConnectTO: "2s", MaxRetries: outInt(5), Health: "1s", Shutdown: "20s",
		})
		// Produce events until the stalled connection made the agent retry.
		retried := func() bool {
			for _, h := range ofType(a.Events(), "agent.health") {
				if outOutput(h, "tcp", "retries") >= 1 {
					return true
				}
			}
			return false
		}
		for round := 0; !retried(); round++ {
			if round == 8 {
				t.Fatal("40 MB of events did not stall the TCP connection: the send buffer is larger than expected")
			}
			root := d.outBurst(tk.Root(), 300, 3000, 2)
			outBurstDone(t, root, 10*time.Minute)
			time.Sleep(1500 * time.Millisecond)
		}
		outWait(t, 30*time.Second, "the second connection", func() bool { return srv.NumConns() >= 2 })
		srv.Release(0) // the old connection is read to its end now
		evs := outStopAndEvents(t, a)
		outWait(t, 60*time.Second, "all connections to end", srv.AllEnded)
		byID := outByID(evs)
		want := outRemoteEvents(evs)
		conns := srv.Conns()
		stopped := evs[len(evs)-1]
		if n := outOutput(stopped, "tcp", "dropped_queue_full"); n != 0 {
			t.Fatalf("%d events were dropped because the queue was full; the test needs all of them", n)
		}

		// Every event of the log arrived complete at least once, identical to the log line.
		got := outAssertIdentical(t, "tcp", srv.LineBytes(), byID)
		if miss := outMissing(want, got); len(miss) > 0 {
			t.Errorf("%d events never arrived complete, e.g. %v", len(miss), miss[:min(3, len(miss))])
		}
		dups := 0
		for _, n := range got {
			dups += n - 1
		}

		// The first line of the second connection is the retried event; the
		// stalled connection ended in a fragment of it, or in no fragment if
		// not a single byte of the line fitted into the socket.
		first := conns[1]
		if len(first.Lines) == 0 {
			t.Fatal("the second connection received nothing")
		}
		retriedID := outEventID(first.Lines[0])
		for _, l := range conns[0].Lines {
			if outEventID(l) == retriedID {
				t.Errorf("event %s was delivered complete on the stalled connection and sent again", retriedID)
			}
		}
		tail := conns[0].Tail
		if len(tail) > 0 && (!bytes.HasPrefix(first.Lines[0], tail) || len(tail) >= len(first.Lines[0])) {
			t.Errorf("the fragment on the old connection (%d bytes) is not a proper prefix of the first line of the new one", len(tail))
		}
		for i, c := range conns[1:] {
			if len(c.Tail) != 0 {
				t.Errorf("connection %d ends in an unterminated line of %d bytes", i+1, len(c.Tail))
			}
		}
		t.Logf("%d connections; fragment of %d bytes at the end of the first connection; %d complete lines on it, %d on the second; %d duplicates; retries %d",
			len(conns), len(tail), len(conns[0].Lines), len(first.Lines), dups, outOutput(stopped, "tcp", "retries"))
	})
}

// ----------------------------------------------------------------------------
// 5. TCP with TLS: certificate and host name are verified, there is no plaintext fallback

func TestOutTCPTLS(t *testing.T) {
	requireRoot(t)
	good, bad := time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour)
	loopback := []net.IP{net.IPv4(127, 0, 0, 1)}

	type tlsCase struct {
		name       string
		dns        []string
		ips        []net.IP
		notBefore  time.Time
		notAfter   time.Time
		trust      string // "server" (the CA that issued the certificate), "other" (an unrelated CA), "system" (no ca_file)
		serverName string // tcp.server_name
		plaintext  bool   // the receiver does not speak TLS at all
		wantError  string // "" when delivery has to work; else a text of the error that must be logged
	}
	cases := []tlsCase{
		{name: "IP address in the certificate", ips: loopback, notBefore: good, notAfter: bad, trust: "server"},
		{name: "DNS name in the certificate and server_name", dns: []string{"collector.test"}, notBefore: good, notAfter: bad, trust: "server", serverName: "collector.test"},
		{name: "server_name that is also an IP", ips: loopback, notBefore: good, notAfter: bad, trust: "server", serverName: "127.0.0.1"},
		{name: "wrong server_name", dns: []string{"collector.test"}, notBefore: good, notAfter: bad, trust: "server", serverName: "other.test", wantError: "other.test"},
		{name: "certificate for another address", ips: []net.IP{net.IPv4(192, 0, 2, 1)}, notBefore: good, notAfter: bad, trust: "server", wantError: "192.0.2.1"},
		{name: "unknown CA", ips: loopback, notBefore: good, notAfter: bad, trust: "other", wantError: "unknown authority"},
		{name: "system trust store does not know the CA", ips: loopback, notBefore: good, notAfter: bad, trust: "system", wantError: "authority"},
		{name: "expired certificate", ips: loopback, notBefore: time.Now().Add(-72 * time.Hour), notAfter: time.Now().Add(-24 * time.Hour), trust: "server", wantError: "expired"},
		{name: "plaintext receiver", trust: "server", plaintext: true, wantError: "TLS handshake"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newProgDir(t)
			tk := outNewToken()
			ca := outNewCA(t, "process-watcher test CA")
			var opts outTCPOpts
			if !tc.plaintext {
				cert := ca.issue(t, tc.dns, tc.ips, tc.notBefore, tc.notAfter)
				opts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
			}
			srv := outNewTCPServer(t, opts)
			caDir := t.TempDir()
			cfg := outCfg{Token: tk, TCP: srv.Addr, TLS: true, ServerName: tc.serverName, ConnectTO: "2s", WriteTO: "2s", MaxRetries: outInt(1), Health: "500ms", Shutdown: "2s"}
			switch tc.trust {
			case "server":
				cfg.CAFile = ca.writePEM(t, caDir, "ca.pem")
			case "other":
				cfg.CAFile = outNewCA(t, "some other CA").writePEM(t, caDir, "ca.pem")
			}
			a := outStart(t, cfg)

			root := d.outBurst(tk.Root(), 20, 0, 1)
			pids := outBurstDone(t, root, 10*time.Minute)
			a.waitEvents(60*time.Second, "the root's exit", func(evs []Ev) bool {
				return len(filterEv(ofType(evs, "process.exit"), func(e Ev) bool { return e.PID() == root.PID })) > 0
			})

			if tc.wantError == "" {
				// Delivery works: everything arrives, identical to the log, over TLS.
				a.waitEvents(30*time.Second, "a health event after the burst", func(evs []Ev) bool { return len(ofType(evs, "agent.health")) >= 2 })
				evs := outStopAndEvents(t, a)
				outWait(t, 30*time.Second, "the connection to end", func() bool { return srv.NumConns() > 0 && srv.AllEnded() })
				count := outAssertIdentical(t, "tcp", srv.LineBytes(), outByID(evs))
				if miss := outMissing(outRemoteEvents(evs), count); len(miss) > 0 {
					t.Errorf("%d events did not arrive over TLS, e.g. %v", len(miss), miss[:min(3, len(miss))])
				}
				conns := srv.Conns()
				if len(conns) != 1 || !conns[0].Handshaken {
					t.Errorf("%d connections, handshake completed: %v", len(conns), len(conns) > 0 && conns[0].Handshaken)
				}
				if got := outOutput(evs[len(evs)-1], "tcp", "failed"); got != 0 {
					t.Errorf("tcp failed %d, want 0\n%s", got, a.stderr.String())
				}
				return
			}

			// Delivery must fail: nothing is sent, not even in plaintext.
			evs := outWaitHealth(t, a, 60*time.Second, "a health event with failed tcp events", func(h Ev) bool {
				return outOutput(h, "tcp", "failed") >= 1
			})
			// The agent keeps going: the local log is complete.
			for _, pid := range pids {
				if got := kinds(ofPID(evs, pid)); got != "fork,exec,exit" {
					t.Fatalf("child %d: log records [%s], want fork,exec,exit", pid, got)
				}
			}
			evs = outStopAndEvents(t, a)
			stopped := evs[len(evs)-1]
			if got := outOutput(stopped, "tcp", "handed_over"); got != 0 {
				t.Errorf("tcp handed_over %d, want 0", got)
			}
			for _, c := range srv.Conns() {
				if c.Handshaken {
					t.Errorf("connection %d completed a TLS handshake", c.Index)
				}
				// Nothing but the TLS handshake went over the wire: the first
				// record is a handshake record (0x16) and no event text is in the
				// stream, so there was no fall back to plaintext.
				if len(c.Raw) == 0 || c.Raw[0] != 0x16 {
					t.Errorf("connection %d: the agent did not start with a TLS handshake: first bytes %q", c.Index, outClip(c.Raw))
				}
				if bytes.Contains(c.Raw, []byte("event_id")) || bytes.Contains(c.Raw, []byte("schema_version")) {
					t.Errorf("connection %d: event data went over the wire in plaintext: %q", c.Index, outClip(c.Raw))
				}
			}
			if srv.NumConns() == 0 {
				t.Error("the agent never connected")
			}
			stderr := a.stderr.String()
			if !strings.Contains(stderr, tc.wantError) {
				t.Errorf("stderr does not mention %q:\n%s", tc.wantError, stderr)
			}
			if lower := strings.ToLower(stderr); !strings.Contains(lower, "tls") && !strings.Contains(lower, "x509") && !strings.Contains(lower, "certificate") {
				t.Errorf("stderr does not name a certificate or handshake problem:\n%s", stderr)
			}
			if strings.Contains(stderr, "PRIVATE KEY") || strings.Contains(stderr, "BEGIN") {
				t.Errorf("stderr contains key or certificate material:\n%s", stderr)
			}
		})
	}

	// A ca_file that cannot be used is a configuration error (exit code 2) and
	// observation does not start. check-config, which exists to find such
	// errors without side effects, has to agree with run.
	t.Run("unusable ca_file is a configuration error", func(t *testing.T) {
		dir := t.TempDir()
		notPEM := filepath.Join(dir, "not-a-ca.pem")
		if err := os.WriteFile(notPEM, []byte("this is not a certificate\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct{ name, path string }{
			{"missing", filepath.Join(dir, "missing.pem")},
			{"without a certificate", notPEM},
		} {
			t.Run(tc.name, func(t *testing.T) {
				logPath := filepath.Join(t.TempDir(), "events.jsonl")
				cfg := outCfg{Token: outNewToken(), TCP: "127.0.0.1:9", TLS: true, CAFile: tc.path, LogPath: logPath}
				cfgPath := filepath.Join(t.TempDir(), "config.yaml")
				if err := os.WriteFile(cfgPath, []byte(cfg.render(logPath)), 0o600); err != nil {
					t.Fatal(err)
				}
				code, out := outRunAgent(t, nil, "--config", cfgPath)
				if code != 2 || !strings.Contains(out, tc.path) {
					t.Errorf("run: exit %d, want 2 and a message that names %s:\n%s", code, tc.path, out)
				}
				if raw, _ := os.ReadFile(logPath); bytes.Contains(raw, []byte("agent.started")) {
					t.Error("run started to observe although its configuration is unusable")
				}
				if code, out := outRunAgent(t, nil, "check-config", "--config", cfgPath); code == 0 {
					t.Errorf("check-config accepts a configuration that run refuses with exit code 2:\n%s", out)
				}
			})
		}
	})
}

// ----------------------------------------------------------------------------
// 6. UDP: an event above max_bytes is dropped for UDP only

func TestOutUDPSizeLimit(t *testing.T) {
	requireRoot(t)
	// Ordinary events are between 1.0 and 1.9 KB. With a 2000 byte argument the
	// exec and exit events of a child grow to about 3.5 KB; the fork event of
	// the same child inherits the short arguments of its parent.
	for _, limit := range []int{2560, 512} {
		t.Run(fmt.Sprintf("max_bytes %d", limit), func(t *testing.T) {
			tcp := outNewTCPServer(t, outTCPOpts{})
			udp := outNewUDPServer(t)
			hook := outNewHookServer(t)
			d := newProgDir(t)
			tk := outNewToken()
			a := outStart(t, outCfg{Token: tk, CaptureArgv: true, TCP: tcp.Addr, UDP: udp.Addr, UDPMax: limit, Webhook: hook.URL, Health: "500ms"})
			const children = 40
			root := d.outBurst(tk.Root(), children, 2000, 1)
			outBurstDone(t, root, 10*time.Minute)
			outWaitAfterExit(t, a, root.PID, 60*time.Second)
			evs := outStopAndEvents(t, a)
			stopped := evs[len(evs)-1]
			byID := outByID(evs)
			want := outRemoteEvents(evs)

			var tooLarge, fits []Ev
			for _, e := range want {
				if len(e.Line)+1 > limit {
					tooLarge = append(tooLarge, e)
				} else {
					fits = append(fits, e)
				}
			}
			if limit > 512 && (len(tooLarge) < 2*children || len(fits) < 3) {
				t.Fatalf("test setup: %d events above and %d at or below %d bytes", len(tooLarge), len(fits), limit)
			}
			if limit == 512 && len(fits) != 0 {
				t.Fatalf("test setup: %d events are not above the minimum limit", len(fits))
			}

			// UDP: exactly the events that fit; each datagram is one complete line.
			handed := outOutput(stopped, "udp", "handed_over")
			outWaitDatagrams(udp, handed, 20*time.Second)
			dgrams := udp.Datagrams()
			count := outAssertIdentical(t, "udp", dgrams, byID)
			for i, dg := range dgrams {
				if len(dg) > limit {
					t.Errorf("datagram %d has %d bytes, the limit is %d", i, len(dg), limit)
				}
			}
			for _, e := range tooLarge {
				if count[e.str("event_id")] != 0 {
					t.Errorf("udp received %s %s of %d bytes above the limit %d", e.Type(), e.str("event_id"), len(e.Line)+1, limit)
				}
			}
			lost := len(outMissing(fits, count))
			if lost > len(fits)/20 {
				t.Errorf("udp lost %d of %d events that fit", lost, len(fits))
			}
			if got := outOutput(stopped, "udp", "dropped_too_large"); got != len(tooLarge) {
				t.Errorf("udp dropped_too_large %d, want %d (the events above %d bytes)", got, len(tooLarge), limit)
			}
			// The counter is in the health data too, not only in agent.stopped.
			healthCounts := 0
			for _, h := range ofType(evs, "agent.health") {
				healthCounts = max(healthCounts, outOutput(h, "udp", "dropped_too_large"))
			}
			if healthCounts == 0 || healthCounts > len(tooLarge) {
				t.Errorf("the largest dropped_too_large in an agent.health event is %d, want between 1 and %d", healthCounts, len(tooLarge))
			}
			if got := outOutput(stopped, "udp", "handed_over"); got != len(fits) {
				t.Errorf("udp handed_over %d, want %d", got, len(fits))
			}
			if got := outOutput(stopped, "udp", "failed") + outOutput(stopped, "udp", "dropped_queue_full"); got != 0 {
				t.Errorf("udp failed or queue-full: %d", got)
			}
			t.Logf("limit %d: %d events fit, %d too large; udp received %d (agent handed over %d)", limit, len(fits), len(tooLarge), len(count), handed)

			// The other outputs and the file have every event, large ones in full.
			outWait(t, 30*time.Second, "the TCP connection to end", func() bool { return tcp.NumConns() > 0 && tcp.AllEnded() })
			var hookBodies [][]byte
			for _, r := range hook.Accepted() {
				hookBodies = append(hookBodies, r.Body)
			}
			for name, got := range map[string][][]byte{"tcp": tcp.LineBytes(), "webhook": hookBodies} {
				c := outAssertIdentical(t, name, got, byID)
				if miss := outMissing(want, c); len(miss) > 0 {
					t.Errorf("%s is missing %d events, e.g. %v", name, len(miss), miss[:min(3, len(miss))])
				}
				large := 0
				for _, e := range tooLarge {
					if c[e.str("event_id")] == 1 {
						large++
					}
				}
				if large != len(tooLarge) {
					t.Errorf("%s has %d of the %d large events", name, large, len(tooLarge))
				}
				if got := outOutput(stopped, name, "handed_over"); got != len(want) {
					t.Errorf("%s handed_over %d, want %d", name, got, len(want))
				}
				if got := outOutput(stopped, name, "dropped_too_large"); got != 0 {
					t.Errorf("%s dropped_too_large %d, want 0", name, got)
				}
			}
			// The log holds the large lines in full and complete: the child's argument is there.
			var withArg int
			for _, e := range tooLarge {
				for _, arg := range e.argv() {
					if len(arg) == 2000 {
						withArg++
					}
				}
			}
			if withArg != len(tooLarge) && limit > 512 {
				t.Errorf("%d of %d large events carry the full 2000 byte argument", withArg, len(tooLarge))
			}
		})
	}
}

// ----------------------------------------------------------------------------
// 7. Webhook: status handling, retries, redirects, timeouts and secrets

// outHookRun is a finished run of an agent against a scripted webhook receiver.
type outHookRun struct {
	hook    *outHookServer
	a       *agent
	evs     []Ev
	started Ev
	stopped Ev
	reqs    []outHookReq
}

// outHookScenario starts the receiver with the script and an agent that
// delivers to it, waits until the scripted answers are used up and the later
// events were delivered, and stops the agent.
func outHookScenario(t *testing.T, script []outHookStep, mod func(*outCfg)) *outHookRun {
	t.Helper()
	hook := outNewHookServer(t, script...)
	cfg := outCfg{Token: outNewToken(), Webhook: hook.URL + "/hook", Health: "500ms", ConnectTO: "1s", WriteTO: "2s", Shutdown: "10s"}
	if mod != nil {
		mod(&cfg)
	}
	a := outStart(t, cfg)
	outWaitHealth(t, a, 120*time.Second, "the webhook to deliver events after the scripted answers", func(h Ev) bool {
		return outOutput(h, "webhook", "handed_over") >= 2
	})
	evs := outStopAndEvents(t, a)
	r := &outHookRun{hook: hook, a: a, evs: evs, started: ofType(evs, "agent.started")[0], stopped: evs[len(evs)-1], reqs: hook.Requests()}
	if len(r.reqs) == 0 {
		t.Fatal("the webhook received no request")
	}
	return r
}

func (r *outHookRun) stat(key string) int { return outOutput(r.stopped, "webhook", key) }

// carrying returns the requests that carry the event id.
func (r *outHookRun) carrying(id string) []outHookReq {
	var out []outHookReq
	for _, q := range r.reqs {
		if q.Header.Get("X-Event-ID") == id {
			out = append(out, q)
		}
	}
	return out
}

// sameEvent asserts that both requests repeat the started event: same body,
// same X-Event-ID, body equal to the log line.
func (r *outHookRun) sameEvent(t *testing.T, a, b outHookReq) {
	t.Helper()
	id := r.started.str("event_id")
	for _, q := range []outHookReq{a, b} {
		if got := q.Header.Get("X-Event-ID"); got != id {
			t.Errorf("request %d: X-Event-ID %q, want %q", q.N, got, id)
		}
		if string(q.Body) != r.started.Line+"\n" {
			t.Errorf("request %d: the body is not the log line of agent.started", q.N)
		}
	}
	if !bytes.Equal(a.Body, b.Body) {
		t.Errorf("requests %d and %d carry different bodies", a.N, b.N)
	}
}

// accounted asserts that every offered event was delivered or counted as failed.
func (r *outHookRun) accounted(t *testing.T, wantFailed int) {
	t.Helper()
	offered := len(outRemoteEvents(r.evs))
	if got := r.stat("failed"); got != wantFailed {
		t.Errorf("failed %d, want %d", got, wantFailed)
	}
	if got := r.stat("handed_over") + r.stat("failed") + r.stat("dropped_queue_full"); got != offered {
		t.Errorf("handed_over %d + failed %d + dropped %d != %d offered", r.stat("handed_over"), r.stat("failed"), r.stat("dropped_queue_full"), offered)
	}
	if got := len(r.hook.Accepted()); got != r.stat("handed_over") {
		t.Errorf("the receiver answered %d requests with 2xx, the agent counts %d handed over", got, r.stat("handed_over"))
	}
}

func TestOutWebhookBehaviour(t *testing.T) {
	// The scripted answers apply to the first event, agent.started; every later
	// request is answered with 200.
	t.Run("500 then 200 repeats the same event", func(t *testing.T) {
		requireRoot(t)
		r := outHookScenario(t, []outHookStep{{Status: 500}}, nil)
		if len(r.reqs) < 3 || r.reqs[0].Status != 500 || r.reqs[1].Status != 200 {
			t.Fatalf("answers: %+v", r.reqs)
		}
		r.sameEvent(t, r.reqs[0], r.reqs[1])
		if gap := r.reqs[1].At.Sub(r.reqs[0].At); gap < 700*time.Millisecond || gap > 15*time.Second {
			t.Errorf("the retry came %s after the failed attempt, want about 1s of backoff", gap)
		}
		if n := len(r.carrying(r.started.str("event_id"))); n != 2 {
			t.Errorf("agent.started was sent %d times, want 2", n)
		}
		if got := r.stat("retries"); got != 1 {
			t.Errorf("retries %d, want 1", got)
		}
		// handed_over counts the event once, although it took two requests.
		if got, want := len(r.reqs), r.stat("handed_over")+1; got != want {
			t.Errorf("%d requests, but %d handed over: want exactly one more request than events", got, r.stat("handed_over"))
		}
		r.accounted(t, 0)
	})

	t.Run("400 is final", func(t *testing.T) {
		requireRoot(t)
		r := outHookScenario(t, []outHookStep{{Status: 400}}, nil)
		if n := len(r.carrying(r.started.str("event_id"))); n != 1 {
			t.Errorf("agent.started was sent %d times, a 400 must not be retried", n)
		}
		if r.reqs[0].Status != 400 {
			t.Fatalf("answers: %+v", r.reqs)
		}
		if got := r.stat("retries"); got != 0 {
			t.Errorf("retries %d, want 0", got)
		}
		r.accounted(t, 1)
		if !strings.Contains(r.a.stderr.String(), "400") {
			t.Errorf("stderr does not report the rejected event:\n%s", r.a.stderr.String())
		}
	})

	t.Run("429 with Retry-After waits at least that long", func(t *testing.T) {
		requireRoot(t)
		// Three seconds: more than the longest first backoff (1s plus 20%), so
		// only an honoured Retry-After explains the pause.
		r := outHookScenario(t, []outHookStep{{Status: 429, Header: map[string]string{"Retry-After": "3"}}}, nil)
		if len(r.reqs) < 3 || r.reqs[0].Status != 429 || r.reqs[1].Status != 200 {
			t.Fatalf("answers: %+v", r.reqs)
		}
		r.sameEvent(t, r.reqs[0], r.reqs[1])
		if gap := r.reqs[1].At.Sub(r.reqs[0].At); gap < 2900*time.Millisecond || gap > 20*time.Second {
			t.Errorf("the retry came %s after the 429 with Retry-After: 3", gap)
		}
		if got := r.stat("retries"); got != 1 {
			t.Errorf("retries %d, want 1", got)
		}
		r.accounted(t, 0)
	})

	t.Run("429 with a Retry-After date waits until then", func(t *testing.T) {
		requireRoot(t)
		// The date has a resolution of one second: waiting until it means 3 to 4 seconds here.
		r := outHookScenario(t, []outHookStep{{Status: 429, RetryAfterDate: 4 * time.Second}}, nil)
		if len(r.reqs) < 3 || r.reqs[0].Status != 429 || r.reqs[1].Status != 200 {
			t.Fatalf("answers: %+v", r.reqs)
		}
		r.sameEvent(t, r.reqs[0], r.reqs[1])
		if gap := r.reqs[1].At.Sub(r.reqs[0].At); gap < 2500*time.Millisecond || gap > 20*time.Second {
			t.Errorf("the retry came %s after a 429 with a Retry-After date 4s ahead", gap)
		}
		r.accounted(t, 0)
	})

	t.Run("a response body that never ends does not hold the agent", func(t *testing.T) {
		requireRoot(t)
		// Only a bounded part of the answer is read and the body is closed; the
		// event counts as delivered and the next request follows at once, not
		// after the 4s request timeout.
		r := outHookScenario(t, []outHookStep{{StallBody: true}}, func(c *outCfg) { c.WebhookTimeout = "4s" })
		if len(r.reqs) < 3 || r.reqs[0].Status != 200 {
			t.Fatalf("answers: %+v", r.reqs)
		}
		if n := len(r.carrying(r.started.str("event_id"))); n != 1 {
			t.Errorf("agent.started was sent %d times although the answer was 200", n)
		}
		if gap := r.reqs[1].At.Sub(r.reqs[0].At); gap > 2*time.Second {
			t.Errorf("the next request came %s after the one with the endless body: the agent waited for the end of the body", gap)
		}
		if got := r.stat("retries") + r.stat("failed"); got != 0 {
			t.Errorf("retries+failed %d, want 0", got)
		}
		r.accounted(t, 0)
	})

	t.Run("503 with Retry-After is retried after that time", func(t *testing.T) {
		requireRoot(t)
		r := outHookScenario(t, []outHookStep{{Status: 503, Header: map[string]string{"Retry-After": "2"}}}, nil)
		if len(r.reqs) < 3 || r.reqs[0].Status != 503 || r.reqs[1].Status != 200 {
			t.Fatalf("answers: %+v", r.reqs)
		}
		r.sameEvent(t, r.reqs[0], r.reqs[1])
		if gap := r.reqs[1].At.Sub(r.reqs[0].At); gap < 1900*time.Millisecond || gap > 20*time.Second {
			t.Errorf("the retry came %s after the 503 with Retry-After: 2", gap)
		}
		r.accounted(t, 0)
	})

	t.Run("408 is retried", func(t *testing.T) {
		requireRoot(t)
		r := outHookScenario(t, []outHookStep{{Status: 408}}, nil)
		if len(r.reqs) < 3 || r.reqs[0].Status != 408 || r.reqs[1].Status != 200 {
			t.Fatalf("answers: %+v", r.reqs)
		}
		r.sameEvent(t, r.reqs[0], r.reqs[1])
		if got := r.stat("retries"); got != 1 {
			t.Errorf("retries %d, want 1", got)
		}
		r.accounted(t, 0)
	})

	t.Run("every 2xx is accepted", func(t *testing.T) {
		requireRoot(t)
		r := outHookScenario(t, []outHookStep{{Status: 204}, {Status: 202}}, nil)
		if len(r.reqs) < 3 || r.reqs[0].Status != 204 || r.reqs[1].Status != 202 {
			t.Fatalf("answers: %+v", r.reqs)
		}
		if n := len(r.carrying(r.started.str("event_id"))); n != 1 {
			t.Errorf("agent.started was sent %d times although 204 is a success", n)
		}
		if got := r.stat("retries") + r.stat("failed"); got != 0 {
			t.Errorf("retries+failed %d, want 0", got)
		}
		r.accounted(t, 0)
	})

	t.Run("302 is not followed and counts as failed", func(t *testing.T) {
		requireRoot(t)
		r := outHookScenario(t, []outHookStep{{Status: 302, Header: map[string]string{"Location": "/elsewhere"}}}, nil)
		for _, q := range r.reqs {
			if q.Path == "/elsewhere" {
				t.Errorf("the agent followed the redirect (request %d)", q.N)
			}
		}
		if n := len(r.carrying(r.started.str("event_id"))); n != 1 {
			t.Errorf("agent.started was sent %d times, a redirect is final", n)
		}
		if got := r.stat("retries"); got != 0 {
			t.Errorf("retries %d, want 0", got)
		}
		r.accounted(t, 1)
		if !strings.Contains(r.a.stderr.String(), "302") {
			t.Errorf("stderr does not report the redirect:\n%s", r.a.stderr.String())
		}
	})

	t.Run("no answer within the timeout is retried", func(t *testing.T) {
		requireRoot(t)
		r := outHookScenario(t, []outHookStep{{Hang: true}}, func(c *outCfg) { c.WebhookTimeout = "1s" })
		if len(r.reqs) < 3 || r.reqs[0].Done || r.reqs[1].Status != 200 {
			t.Fatalf("answers: %+v", r.reqs)
		}
		r.sameEvent(t, r.reqs[0], r.reqs[1])
		if gap := r.reqs[1].At.Sub(r.reqs[0].At); gap < 1500*time.Millisecond || gap > 20*time.Second {
			t.Errorf("the retry came %s after the unanswered request, want the 1s timeout plus the backoff", gap)
		}
		if got := r.stat("retries"); got != 1 {
			t.Errorf("retries %d, want 1", got)
		}
		r.accounted(t, 0)
	})

	t.Run("timeouts end after max_retries", func(t *testing.T) {
		requireRoot(t)
		r := outHookScenario(t, []outHookStep{{Hang: true}, {Hang: true}, {Hang: true}}, func(c *outCfg) {
			c.WebhookTimeout = "1s"
			c.MaxRetries = outInt(2)
		})
		id := r.started.str("event_id")
		if n := len(r.carrying(id)); n != 3 {
			t.Errorf("agent.started was sent %d times, want max_retries+1 = 3", n)
		}
		if len(r.reqs) < 4 || r.reqs[3].Header.Get("X-Event-ID") == id {
			t.Fatalf("the agent did not go on to the next event after giving up")
		}
		for i := 1; i < 3; i++ {
			r.sameEvent(t, r.reqs[0], r.reqs[i])
		}
		if got := r.stat("retries"); got != 2 {
			t.Errorf("retries %d, want 2", got)
		}
		// 1s timeouts with backoffs of about 1s and 2s between three attempts.
		if gap := r.reqs[2].At.Sub(r.reqs[0].At); gap < 4*time.Second {
			t.Errorf("three attempts within %s, the backoff doubles from 1s", gap)
		}
		r.accounted(t, 1)
	})

	t.Run("bearer token from token_env", func(t *testing.T) {
		requireRoot(t)
		token := "tok-" + outRandomHex(16)
		envName := "PW_OUT_TOKEN_" + strings.ToUpper(outRandomHex(4))
		t.Setenv(envName, token)
		// Two failing answers make the agent log delivery errors, which must not leak the token.
		r := outHookScenario(t, []outHookStep{{Status: 500}, {Status: 500}}, func(c *outCfg) { c.TokenEnv = envName })
		for _, q := range r.reqs {
			if got := q.Header.Get("Authorization"); got != "Bearer "+token {
				t.Errorf("request %d: Authorization %q, want the bearer token", q.N, got)
			}
		}
		if got := r.stat("retries"); got != 2 {
			t.Errorf("retries %d, want 2 (two 500 answers)", got)
		}
		r.accounted(t, 0)
		outAssertNoSecret(t, r.a, token)
		if !strings.Contains(r.a.stderr.String(), "500") {
			t.Errorf("stderr has no delivery error; the secret check proves nothing:\n%s", r.a.stderr.String())
		}
	})

	// print-config and check-config run without root and never contact the
	// target; they must not print the token or the secrets of the URL either.
	t.Run("print-config and check-config hide the secrets", func(t *testing.T) {
		requireAgentBinary(t)
		token := "tok-" + outRandomHex(16)
		envName := "PW_OUT_TOKEN_" + strings.ToUpper(outRandomHex(4))
		dir := t.TempDir()
		logPath := filepath.Join(dir, "events.jsonl")
		cfg := outCfg{Token: outNewToken(), LogPath: logPath, TokenEnv: envName,
			Webhook: "https://hooks.example.test/hooks/PATHSECRET789/send?key=SECRET123"}
		cfgPath := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(cfgPath, []byte(cfg.render(logPath)), 0o600); err != nil {
			t.Fatal(err)
		}
		env := append(os.Environ(), envName+"="+token)
		for _, sub := range []string{"print-config", "check-config"} {
			code, out := outRunAgent(t, env, sub, "--config", cfgPath)
			if code != 0 {
				t.Errorf("%s: exit %d\n%s", sub, code, out)
			}
			for _, secret := range []string{token, "SECRET123"} {
				if strings.Contains(out, secret) {
					t.Errorf("%s prints the secret %q:\n%s", sub, secret, out)
				}
			}
			// The log lines of the agent hide the path of the URL as well: chat
			// services keep their secret there (output.redactURL).
			if strings.Contains(out, "PATHSECRET789") {
				t.Errorf("%s prints the secret path of the webhook URL (the delivery diagnostics hide it, internal/output/redact.go):\n%s", sub, out)
			}
		}
		if _, err := os.Stat(logPath); err == nil {
			t.Error("print-config or check-config created the log file")
		}
	})

	t.Run("secret in the URL stays out of the logs", func(t *testing.T) {
		requireRoot(t)
		// Chat services put the secret into the path, others into the query.
		const secret, pathSecret = "SECRET123", "PATHSECRET789"
		urlPath := "/hooks/" + pathSecret + "/send"
		t.Run("status errors", func(t *testing.T) {
			hook := outNewHookServer(t, outHookStep{Status: 500}, outHookStep{Status: 500})
			a := outStart(t, outCfg{Token: outNewToken(), Webhook: hook.URL + urlPath + "?key=" + secret, Health: "500ms", Shutdown: "10s"})
			outWaitHealth(t, a, 60*time.Second, "events delivered after two retries", func(h Ev) bool {
				return outOutput(h, "webhook", "handed_over") >= 2
			})
			outStopAndEvents(t, a)
			for _, q := range hook.Requests() {
				if q.Path != urlPath || q.RawQuery != "key="+secret {
					t.Errorf("request %d: %s?%s, the agent must send the URL as configured", q.N, q.Path, q.RawQuery)
				}
			}
			if !strings.Contains(a.stderr.String(), "webhook") {
				t.Errorf("stderr has no delivery error; the secret check proves nothing:\n%s", a.stderr.String())
			}
			outAssertNoSecret(t, a, secret, pathSecret)
		})
		t.Run("connection errors", func(t *testing.T) {
			// Go's HTTP client quotes the URL in its errors; the agent must not pass it on.
			closed := outClosedAddr(t)
			a := outStart(t, outCfg{
				Token: outNewToken(), Webhook: "http://" + closed + urlPath + "?key=" + secret, Health: "300ms",
				MaxRetries: outInt(1), ConnectTO: "1s", Shutdown: "2s",
			})
			outWaitHealth(t, a, 60*time.Second, "a failed webhook event", func(h Ev) bool { return outOutput(h, "webhook", "failed") >= 1 })
			outStopAndEvents(t, a)
			if !strings.Contains(a.stderr.String(), "webhook") || !strings.Contains(a.stderr.String(), "refused") {
				t.Errorf("stderr has no connection error; the secret check proves nothing:\n%s", a.stderr.String())
			}
			outAssertNoSecret(t, a, secret, pathSecret)
		})
	})

	// HTTPS: the certificate and the host name are verified against the system
	// trust store (the agent has no setting to turn that off). SSL_CERT_FILE adds
	// the CA of the test to the roots the agent uses.
	for _, tc := range []struct {
		name  string
		trust bool // the receiver's CA is known to the agent
		ips   []net.IP
		want  bool // delivery has to work
	}{
		{"https with a certificate of a trusted CA is delivered", true, []net.IP{net.IPv4(127, 0, 0, 1)}, true},
		{"https with a certificate nobody trusts is refused", false, []net.IP{net.IPv4(127, 0, 0, 1)}, false},
		{"https with a certificate for another host is refused", true, []net.IP{net.IPv4(192, 0, 2, 1)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireRoot(t)
			ca := outNewCA(t, "process-watcher test CA")
			from, to := outValidity()
			cert := ca.issue(t, nil, tc.ips, from, to)
			hook := outNewHookServerTLS(t, &cert)
			if tc.trust {
				t.Setenv("SSL_CERT_FILE", ca.writePEM(t, t.TempDir(), "roots.pem"))
			}
			const secret = "HTTPSSECRET456"
			a := outStart(t, outCfg{
				Token: outNewToken(), Webhook: hook.URL + "/hook?key=" + secret, Health: "500ms", ConnectTO: "2s",
				MaxRetries: outInt(1), Shutdown: "2s",
			})
			if tc.want {
				outWaitHealth(t, a, 60*time.Second, "events delivered over https", func(h Ev) bool { return outOutput(h, "webhook", "handed_over") >= 2 })
				evs := outStopAndEvents(t, a)
				var bodies [][]byte
				for _, q := range hook.Accepted() {
					bodies = append(bodies, q.Body)
				}
				count := outAssertIdentical(t, "webhook", bodies, outByID(evs))
				if miss := outMissing(outRemoteEvents(evs), count); len(miss) > 0 {
					t.Errorf("%d events did not arrive over https, e.g. %v", len(miss), miss[:min(3, len(miss))])
				}
			} else {
				outWaitHealth(t, a, 60*time.Second, "failed webhook events", func(h Ev) bool { return outOutput(h, "webhook", "failed") >= 1 })
				evs := outStopAndEvents(t, a)
				if n := hook.Count(); n != 0 {
					t.Errorf("the receiver got %d requests although its certificate cannot be trusted", n)
				}
				if got := outOutput(evs[len(evs)-1], "webhook", "handed_over"); got != 0 {
					t.Errorf("webhook handed_over %d, want 0", got)
				}
				lower := strings.ToLower(a.stderr.String())
				if !strings.Contains(lower, "certificate") && !strings.Contains(lower, "x509") {
					t.Errorf("stderr does not name the certificate problem:\n%s", a.stderr.String())
				}
			}
			outAssertNoSecret(t, a, secret)
		})
	}

	// A token_env whose variable is empty or not set is a configuration error:
	// exit code 2, and nothing is created (not even the log directory).
	for _, tc := range []struct {
		name  string
		empty bool
	}{{"token_env variable not set", false}, {"token_env variable empty", true}} {
		t.Run(tc.name, func(t *testing.T) {
			requireAgentBinary(t)
			dir := t.TempDir()
			envName := "PW_OUT_NOTOKEN_" + strings.ToUpper(outRandomHex(4))
			logDir := filepath.Join(dir, "never", "created")
			cfg := outCfg{Token: outNewToken(), Webhook: "http://127.0.0.1:9/hook", TokenEnv: envName, LogPath: filepath.Join(logDir, "events.jsonl")}
			cfgPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(cfgPath, []byte(cfg.render(cfg.LogPath)), 0o600); err != nil {
				t.Fatal(err)
			}
			env := os.Environ()
			if tc.empty {
				env = append(env, envName+"=")
			}
			code, out := outRunAgent(t, env, "--config", cfgPath)
			if code != 2 {
				t.Fatalf("exit code %d, want 2:\n%s", code, out)
			}
			if !strings.Contains(out, envName) {
				t.Errorf("the message does not name the variable %s:\n%s", envName, out)
			}
			if _, err := os.Stat(filepath.Join(dir, "never")); err == nil {
				t.Errorf("a configuration error must not create anything, but %s exists", filepath.Join(dir, "never"))
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 1 {
				t.Errorf("%d entries in the directory, want only the configuration file", len(entries))
			}
		})
	}
}

// outRandomHex returns 2n random hex characters.
func outRandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// outAssertNoSecret asserts that none of the secrets appears in the agent's
// stderr or in any file of its log.
func outAssertNoSecret(t *testing.T, a *agent, secrets ...string) {
	t.Helper()
	var all []byte
	entries, _ := os.ReadDir(filepath.Dir(a.LogPath))
	for _, e := range entries {
		if b, err := os.ReadFile(filepath.Join(filepath.Dir(a.LogPath), e.Name())); err == nil && strings.HasPrefix(e.Name(), filepath.Base(a.LogPath)) {
			all = append(all, b...)
		}
	}
	for _, s := range secrets {
		if bytes.Contains(all, []byte(s)) {
			t.Errorf("the secret %q appears in the log", s)
		}
		if strings.Contains(a.stderr.String(), s) {
			t.Errorf("the secret %q appears in stderr:\n%s", s, a.stderr.String())
		}
	}
}

// ----------------------------------------------------------------------------
// 8. SIGTERM with a long webhook queue: bounded shutdown with exact leftovers

func TestOutShutdownWithQueuedEvents(t *testing.T) {
	requireRoot(t)
	const shutdown = 3 * time.Second
	hook := outNewHookServer(t)
	hook.SetDefault(outHookStep{Delay: 300 * time.Millisecond}) // a slow receiver: about 3 events per second
	d := newProgDir(t)
	tk := outNewToken()
	a := outStart(t, outCfg{Token: tk, Webhook: hook.URL, Health: "300ms", Shutdown: shutdown.String(), WriteTO: "2s"})

	root := d.outBurst(tk.Root(), 150, 0, 2) // about 450 events, far more than the receiver takes in 3s
	outBurstDone(t, root, 10*time.Minute)
	a.waitEvents(60*time.Second, "the root's exit", func(evs []Ev) bool {
		return len(filterEv(ofType(evs, "process.exit"), func(e Ev) bool { return e.PID() == root.PID })) > 0
	})
	outWaitHealth(t, a, 60*time.Second, "a backlog of at least 100 queued events", func(h Ev) bool {
		return outOutput(h, "webhook", "queue_len") >= 100
	})

	before := len(hook.Accepted())
	code, took := outStopTimed(a)
	if code != 0 {
		t.Fatalf("exit code %d, want 0:\n%s", code, a.stderr.String())
	}
	if took > shutdown+5*time.Second {
		t.Errorf("the agent needed %s to stop, shutdown_timeout is %s", took, shutdown)
	}
	if took < shutdown-time.Second {
		t.Errorf("the agent stopped after %s although more than 100 events were queued: the queue is flushed until shutdown_timeout (%s)", took, shutdown)
	}
	evs := a.Events()
	stopped := evs[len(evs)-1]
	if stopped.Type() != "agent.stopped" || stopped.str("details.reason") != "signal" {
		t.Fatalf("the last line is %s (reason %q), want agent.stopped after a signal", stopped.Type(), stopped.str("details.reason"))
	}
	outCheckSequence(t, evs, true)

	offered := len(outRemoteEvents(evs))
	got := map[string]bool{}
	for _, r := range hook.Accepted() {
		got[r.Header.Get("X-Event-ID")] = true
	}
	handed := outOutput(stopped, "webhook", "handed_over")
	undelivered := outCount(stopped, "details.undelivered_at_shutdown.webhook")
	t.Logf("%d events offered; the receiver got %d (%d of them during the shutdown); agent: handed_over %d, undelivered_at_shutdown %d, shutdown took %s",
		offered, len(got), len(hook.Accepted())-before, handed, undelivered, took)

	// The leftover is exactly what the receiver did not get; one request may
	// have been in flight (answered by the receiver, cancelled by the agent).
	if diff := undelivered - (offered - len(got)); diff < -1 || diff > 1 {
		t.Errorf("undelivered_at_shutdown.webhook is %d, but the receiver did not get %d of %d events", undelivered, offered-len(got), offered)
	}
	if len(got) < handed || len(got) > handed+1 {
		t.Errorf("the receiver answered %d events with 2xx, the agent counts %d handed over", len(got), handed)
	}
	if sum := handed + outOutput(stopped, "webhook", "failed") + outOutput(stopped, "webhook", "dropped_queue_full") + undelivered; sum != offered {
		t.Errorf("handed_over %d + failed %d + dropped_queue_full %d + undelivered %d = %d, but %d events were offered",
			handed, outOutput(stopped, "webhook", "failed"), outOutput(stopped, "webhook", "dropped_queue_full"), undelivered, sum, offered)
	}
	if undelivered < 100 {
		t.Errorf("only %d events were left undelivered; the test needs a long queue", undelivered)
	}
	if got := outOutput(stopped, "webhook", "dropped_shutdown"); got != undelivered {
		t.Errorf("outputs.webhook.dropped_shutdown is %d, undelivered_at_shutdown.webhook %d", got, undelivered)
	}
	if during := len(hook.Accepted()) - before; during < 3 {
		t.Errorf("only %d events were delivered during the shutdown: the queue is flushed until shutdown_timeout", during)
	}
	for _, k := range []string{"failed", "retries", "dropped_queue_full"} {
		if got := outOutput(stopped, "webhook", k); got != 0 {
			t.Errorf("outputs.webhook.%s is %d, want 0 (the receiver is slow, not broken)", k, got)
		}
	}
	// The ring buffer holds nothing, and no other output exists.
	if got := outCount(stopped, "details.undelivered_at_shutdown.ring_buffer_bytes"); got != 0 {
		t.Errorf("ring buffer bytes undelivered: %d", got)
	}
}

// ----------------------------------------------------------------------------
// 9. A full disk is fatal and controlled

func TestOutLocalLogFailureIsFatal(t *testing.T) {
	requireRoot(t)

	// mountTmpfs mounts a small tmpfs and removes it when the test ends. The
	// cleanup is registered after TempDir's own and before the agent's: the agent
	// is stopped first, then the mount goes, then the directory.
	mountTmpfs := func(t *testing.T, flags uintptr, size int) string {
		t.Helper()
		mnt := t.TempDir()
		if err := unix.Mount("tmpfs", mnt, "tmpfs", flags, "size="+strconv.Itoa(size)); err != nil {
			t.Skipf("cannot mount a small tmpfs (%v); this scenario needs CAP_SYS_ADMIN and tmpfs", err)
		}
		t.Cleanup(func() {
			if err := unix.Unmount(mnt, unix.MNT_DETACH); err != nil {
				t.Logf("unmount %s: %v", mnt, err)
			}
		})
		return mnt
	}

	t.Run("the disk fills up while the agent runs", func(t *testing.T) {
		size := max(16*os.Getpagesize(), 64<<10)
		mnt := mountTmpfs(t, 0, size)
		udp := outNewUDPServer(t)
		d := newProgDir(t)
		tk := outNewToken()
		logPath := filepath.Join(mnt, "events.jsonl")
		a := outStart(t, outCfg{Token: tk, LogPath: logPath, UDP: udp.Addr, CaptureArgv: true, Health: "500ms", Shutdown: "5s"})

		// Far more events than fit into the tmpfs: about 4.5 KB per child, three times the size.
		root := d.outBurst(tk.Root(), max(100, 3*size/4500), 0, 1)
		outBurstDone(t, root, 10*time.Minute)

		select {
		case <-a.done:
		case <-time.After(15 * time.Second):
			t.Fatalf("the agent is still running 15s after the disk filled up:\n%s", a.stderr.String())
		}
		if a.exit != 1 {
			t.Errorf("exit code %d, want 1 (runtime error)", a.exit)
		}
		stderr := a.stderr.String()
		t.Logf("the agent reports:\n%s", stderr)
		if !strings.Contains(strings.ToLower(stderr), "no space left") {
			t.Errorf("stderr does not say what failed:\n%s", stderr)
		}
		if !strings.Contains(stderr, logPath) && !strings.Contains(stderr, "local log") {
			t.Errorf("stderr does not name the log file:\n%s", stderr)
		}

		// The log holds complete lines only and was not left with a torn last line.
		lines := outLogLines(t, logPath)
		evs := parseEvents(bytes.Join(lines, []byte("\n")))
		if len(evs) < 3 || len(evs) != len(lines) {
			t.Fatalf("%d lines in the log, %d of them events", len(lines), len(evs))
		}
		if fi, err := os.Stat(logPath); err == nil && fi.Size() > int64(size) {
			t.Errorf("log of %d bytes on a file system of %d", fi.Size(), size)
		}
		outCheckSequence(t, evs, true)
		t.Logf("the log holds %d events (%d bytes), the agent exited with %d", len(evs), len(bytes.Join(lines, []byte("\n"))), a.exit)

		// The UDP receiver got the events up to that point, nothing the log lacks.
		byID := outByID(evs)
		outSettle(t, udp.Count, 10*time.Second)
		got := outAssertIdentical(t, "udp", udp.Datagrams(), byID)
		if lost := len(outMissing(evs, got)); lost > len(evs)/20 {
			t.Errorf("udp lost %d of the %d events that were written before the disk was full", lost, len(evs))
		}
	})

	// A log that cannot be created or written at the start is an error too: the
	// agent does not run without its mandatory log and does not hang.
	t.Run("the log is on a read-only file system", func(t *testing.T) {
		mnt := mountTmpfs(t, unix.MS_RDONLY, 64<<10)
		code, out := outRunAgent(t, nil, "--watch-image-contains", outNewToken().Prefix(), "--log-file", filepath.Join(mnt, "events.jsonl"))
		if code != 1 || !strings.Contains(strings.ToLower(out), "read-only") {
			t.Errorf("exit %d, want 1 and a message that says the file system is read-only:\n%s", code, out)
		}
		if entries, _ := os.ReadDir(mnt); len(entries) != 0 {
			t.Errorf("%d entries were created on the read-only file system", len(entries))
		}
	})

	t.Run("the log directory cannot be created", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "a-file")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		code, out := outRunAgent(t, nil, "--watch-image-contains", outNewToken().Prefix(), "--log-file", filepath.Join(file, "sub", "events.jsonl"))
		if code != 1 || !strings.Contains(strings.ToLower(out), "not a directory") {
			t.Errorf("exit %d, want 1 and a message that says what failed:\n%s", code, out)
		}
	})
}

// ----------------------------------------------------------------------------
// 10. The log file: torn tail, one writer, no symlinks, permissions

func TestOutLogFileSafety(t *testing.T) {
	requireRoot(t)

	t.Run("a torn last line is repaired", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "events.jsonl")
		complete := "{\"legacy\":\"line one\"}\n{\"legacy\":\"line two\"}\n{\"legacy\":\"line three\"}\n"
		tail := `{"schema_version":1,"event_id":"torn-by-a-crash","sequence":4,"event_t`
		if err := os.WriteFile(logPath, []byte(complete+tail), 0o600); err != nil {
			t.Fatal(err)
		}
		a := outStart(t, outCfg{Token: outNewToken(), LogPath: logPath})
		outStopAndEvents(t, a)

		raw, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(raw), complete) {
			t.Errorf("the three complete lines were changed:\n%s", outClip(raw))
		}
		if bytes.Contains(raw, []byte(tail)) || bytes.Contains(raw, []byte("torn-by-a-crash")) {
			t.Error("the torn tail is still in the log")
		}
		lines := outLogLines(t, logPath) // every line is complete JSON, the file ends with a newline
		evs := parseEvents(bytes.Join(lines, []byte("\n")))
		started := ofType(evs, "agent.started")
		if len(lines) < 6 || len(started) != 1 || evs[3].Type() != "agent.started" {
			t.Fatalf("the agent must continue right after the complete lines (%d lines):\n%s", len(lines), summarize(evs, 10))
		}
		repair, _ := started[0].get("details.log_repair").(map[string]any)
		if repair == nil || repair["repaired"] != true || int(repair["bytes"].(float64)) != len(tail) {
			t.Fatalf("agent.started: log_repair %v, want repaired with %d bytes", started[0].get("details.log_repair"), len(tail))
		}
		saved, _ := repair["saved_as"].(string)
		if !regexp.MustCompile(`^` + regexp.QuoteMeta(logPath) + `\.corrupt-\d{8}T\d{6}Z(-\d+)?$`).MatchString(saved) {
			t.Fatalf("saved_as %q, want %s.corrupt-<UTC timestamp>", saved, logPath)
		}
		if got, err := os.ReadFile(saved); err != nil || string(got) != tail {
			t.Errorf("the saved tail is %q (%v), want exactly the %d byte tail", outClip(got), err, len(tail))
		}
		if mode := outPerm(t, saved); mode != 0o600 {
			t.Errorf("the saved tail has mode %o, want 600", mode)
		}
	})

	t.Run("a second writer is refused", func(t *testing.T) {
		tk := outNewToken()
		a := outStart(t, outCfg{Token: tk, Health: "300ms"})
		code, out := outRunAgent(t, nil, "--watch-image-contains", tk.Prefix(), "--log-file", a.LogPath)
		if code != 1 {
			t.Errorf("the second agent exited with %d, want 1:\n%s", code, out)
		}
		if !strings.Contains(strings.ToLower(out), "lock") {
			t.Errorf("the message does not mention the lock:\n%s", out)
		}
		t.Logf("second writer: %s", strings.TrimSpace(out))
		// The first agent is undisturbed: it keeps writing, and the log has one run in it.
		n := len(ofType(a.Events(), "agent.health"))
		a.waitEvents(30*time.Second, "another health event", func(evs []Ev) bool { return len(ofType(evs, "agent.health")) > n })
		evs := outStopAndEvents(t, a)
		runs := map[string]bool{}
		for _, e := range evs {
			runs[e.str("agent_instance_id")] = true
		}
		if len(runs) != 1 {
			t.Errorf("%d agent runs wrote to the log, want 1", len(runs))
		}
		outLogLines(t, a.LogPath)
	})

	t.Run("symlinks are refused", func(t *testing.T) {
		tk := outNewToken()
		dir := t.TempDir()
		target := filepath.Join(dir, "real.jsonl")
		const content = "{\"must\":\"stay\"}\n"
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link.jsonl")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		code, out := outRunAgent(t, nil, "--watch-image-contains", tk.Prefix(), "--log-file", link)
		if code != 1 || !strings.Contains(strings.ToLower(out), "symbolic link") {
			t.Errorf("symlink as the log file: exit %d, want 1 and a message about the symbolic link:\n%s", code, out)
		}
		if b, _ := os.ReadFile(target); string(b) != content {
			t.Errorf("the symlink target was modified: %q", b)
		}

		// The lock file next to the log must not be a symlink either.
		logPath := filepath.Join(dir, "events.jsonl")
		lockTarget := filepath.Join(dir, "lock-target")
		if err := os.WriteFile(lockTarget, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(lockTarget, logPath+".lock"); err != nil {
			t.Fatal(err)
		}
		code, out = outRunAgent(t, nil, "--watch-image-contains", tk.Prefix(), "--log-file", logPath)
		if code != 1 || !strings.Contains(strings.ToLower(out), "symbolic link") {
			t.Errorf("symlink as the lock file: exit %d, want 1 and a message about the symbolic link:\n%s", code, out)
		}
		if b, _ := os.ReadFile(lockTarget); string(b) != "keep" {
			t.Errorf("the target of the lock file symlink was modified: %q", b)
		}
	})

	t.Run("special files are refused without blocking", func(t *testing.T) {
		tk := outNewToken()
		dir := t.TempDir()
		fifo := filepath.Join(dir, "events.fifo")
		if err := unix.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		isDir := filepath.Join(dir, "events.d")
		if err := os.Mkdir(isDir, 0o700); err != nil {
			t.Fatal(err)
		}
		// Opening a FIFO for writing would block without a reader; a device
		// node must not even get a lock file next to it.
		for _, tc := range []struct{ name, path string }{{"fifo", fifo}, {"directory", isDir}, {"device", "/dev/null"}} {
			code, out := outRunAgent(t, nil, "--watch-image-contains", tk.Prefix(), "--log-file", tc.path)
			if code == 0 || !strings.Contains(strings.ToLower(out), "regular file") {
				t.Errorf("%s as the log file: exit %d, want a refusal that says it is not a regular file:\n%s", tc.name, code, out)
			}
		}
		if _, err := os.Lstat("/dev/null.lock"); err == nil {
			_ = os.Remove("/dev/null.lock")
			t.Error("a lock file was created next to /dev/null")
		}
	})

	t.Run("a restart appends to the log, also after the agent was killed", func(t *testing.T) {
		tk := outNewToken()
		first := outStart(t, outCfg{Token: tk, Health: "300ms"})
		first.waitEvents(30*time.Second, "a health event", func(evs []Ev) bool { return len(ofType(evs, "agent.health")) >= 1 })
		if err := first.cmd.Process.Kill(); err != nil { // no orderly shutdown at all
			t.Fatal(err)
		}
		<-first.done
		before, err := os.ReadFile(first.LogPath)
		if err != nil || len(before) == 0 || before[len(before)-1] != '\n' {
			t.Fatalf("the killed agent left %d bytes that do not end with a newline (%v)", len(before), err)
		}
		// The lock of the dead agent is gone with it: a new agent starts at once.
		second := outLaunch(t, outCfg{Token: tk, LogPath: first.LogPath, Health: "300ms"})
		second.waitEvents(30*time.Second, "the agent.ready of the second run", func(evs []Ev) bool { return len(ofType(evs, "agent.ready")) >= 2 })
		pid, _ := os.ReadFile(first.LogPath + ".lock")
		if got := strings.TrimSpace(string(pid)); got != strconv.Itoa(second.cmd.Process.Pid) {
			t.Errorf("the lock file names %q, the running agent is %d", got, second.cmd.Process.Pid)
		}
		evs := outStopAndEvents(t, second)
		raw, _ := os.ReadFile(first.LogPath)
		if !bytes.HasPrefix(raw, before) {
			t.Error("the first run's lines are not at the start of the log any more")
		}
		started := ofType(evs, "agent.started")
		if len(started) != 2 || started[0].str("agent_instance_id") == started[1].str("agent_instance_id") {
			t.Fatalf("%d agent.started events, want one per run with different agent_instance_id", len(started))
		}
		if started[1].get("details.log_repair") != nil {
			t.Errorf("the log ended in a complete line, no repair expected: %v", started[1].get("details.log_repair"))
		}
		if got := started[1].Seq(); got != 1 {
			t.Errorf("the sequence of a new run starts at %d, want 1", got)
		}
		outLogLines(t, first.LogPath)
	})

	t.Run("permissions of created files and directories", func(t *testing.T) {
		// With umask 0 the result cannot come from the umask hiding wide modes.
		old := syscall.Umask(0)
		t.Cleanup(func() { syscall.Umask(old) })
		base := t.TempDir()
		logPath := filepath.Join(base, "a", "b", "c", "events.jsonl")
		a := outStart(t, outCfg{Token: outNewToken(), LogPath: logPath})
		for _, dir := range []string{"a", "a/b", "a/b/c"} {
			if mode := outPerm(t, filepath.Join(base, dir)); mode != 0o700 {
				t.Errorf("directory %s created with mode %o, want 700", dir, mode)
			}
		}
		for _, f := range []string{logPath, logPath + ".lock"} {
			if mode := outPerm(t, f); mode != 0o600 {
				t.Errorf("%s created with mode %o, want 600", filepath.Base(f), mode)
			}
		}
		if started := ofType(a.Events(), "agent.started"); len(started) != 1 || started[0].get("details.log_repair") != nil {
			t.Errorf("a new log must not report a repair: %v", started[0].get("details.log_repair"))
		}
		outStopAndEvents(t, a)
	})

	t.Run("existing permissions are not widened or changed", func(t *testing.T) {
		old := syscall.Umask(0)
		t.Cleanup(func() { syscall.Umask(old) })
		base := t.TempDir()
		existing := filepath.Join(base, "existing")
		if err := os.Mkdir(existing, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(existing, 0o755); err != nil {
			t.Fatal(err)
		}
		logPath := filepath.Join(existing, "events.jsonl")
		if err := os.WriteFile(logPath, []byte("{\"old\":true}\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(logPath, 0o640); err != nil {
			t.Fatal(err)
		}
		a := outStart(t, outCfg{Token: outNewToken(), LogPath: logPath})
		if mode := outPerm(t, existing); mode != 0o755 {
			t.Errorf("the existing directory was changed to %o", mode)
		}
		if mode := outPerm(t, logPath); mode != 0o640 {
			t.Errorf("the existing log file was changed to %o, want its mode 640 left alone", mode)
		}
		if !strings.Contains(a.stderr.String(), "0600") {
			t.Errorf("a log file that is more open than 0600 is not reported:\n%s", a.stderr.String())
		}
		outStopAndEvents(t, a)
		raw, _ := os.ReadFile(logPath)
		if !strings.HasPrefix(string(raw), "{\"old\":true}\n") {
			t.Errorf("the old line is gone")
		}
	})
}

// ----------------------------------------------------------------------------
// 11. Rotation under load with all remote outputs enabled

func TestOutRotationUnderLoad(t *testing.T) {
	requireRoot(t)
	tcp := outNewTCPServer(t, outTCPOpts{})
	udp := outNewUDPServer(t)
	hook := outNewHookServer(t)
	d := newProgDir(t)
	tk := outNewToken()
	logPath := filepath.Join(t.TempDir(), "events.jsonl")
	// Archives of an earlier run with a larger keep_files are removed by the first rotation.
	for _, n := range []string{".4", ".5"} {
		if err := os.WriteFile(logPath+n, []byte("{\"stale\":true}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a := outStart(t, outCfg{
		Token: tk, LogPath: logPath, CaptureArgv: true, RotateMB: 1, KeepFiles: 3, TCP: tcp.Addr, UDP: udp.Addr, Webhook: hook.URL,
		Health: "500ms", Shutdown: "60s",
	})

	// Load until the log has rotated at least five times, so that a fourth
	// archive would exist if keep_files were not enforced.
	rotations := func() int {
		n := 0
		for _, h := range ofType(a.Events(), "agent.health") {
			n = max(n, outOutput(h, "file", "rotations"))
		}
		return n
	}
	for round := 0; rotations() < 5; round++ {
		if round == 25 {
			t.Fatal("25 bursts did not rotate the log five times")
		}
		root := d.outBurst(tk.Root(), 300, 3500, 2)
		outBurstDone(t, root, 10*time.Minute)
		time.Sleep(700 * time.Millisecond) // lets a health event report the rotations
	}
	evs := outStopAndEvents(t, a)
	stopped := evs[len(evs)-1]

	// Archives .1 to .3 exist, nothing beyond.
	for i := 1; i <= 3; i++ {
		if _, err := os.Stat(a.LogPath + "." + strconv.Itoa(i)); err != nil {
			t.Errorf("archive .%d is missing: %v", i, err)
		}
	}
	for i := 4; i <= 6; i++ {
		if _, err := os.Stat(a.LogPath + "." + strconv.Itoa(i)); err == nil {
			t.Errorf("archive .%d exists although keep_files is 3", i)
		}
	}
	if got := outOutput(stopped, "file", "rotations"); got < 5 {
		t.Errorf("rotations %d in agent.stopped, want at least 5", got)
	}
	// Every file holds only complete lines, within the size limit, and is private.
	files := []string{a.LogPath, a.LogPath + ".1", a.LogPath + ".2", a.LogPath + ".3"}
	total := 0
	for _, f := range files {
		total += len(outLogLines(t, f))
		fi, err := os.Stat(f)
		if err != nil {
			continue
		}
		if fi.Size() > 1<<20 {
			t.Errorf("%s has %d bytes, more than rotate_size_mb 1", filepath.Base(f), fi.Size())
		}
		if mode := fi.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s has mode %o, want 600", filepath.Base(f), mode)
		}
	}
	// The retained files are one contiguous run of the sequence: rotation loses nothing.
	retained := a.Events()
	if len(retained) != total {
		t.Fatalf("the harness reads %d events from %d lines", len(retained), total)
	}
	outCheckSequence(t, retained, true)
	if retained[0].Seq() <= 1 {
		t.Errorf("the oldest retained event is #%d: nothing was rotated out", retained[0].Seq())
	}
	if last := retained[len(retained)-1]; last.Type() != "agent.stopped" {
		t.Errorf("the last line is %s", last.Type())
	}

	// The remote outputs saw every event, unaffected by the rotation.
	written := 0
	if events, ok := stopped.get("details.events").(map[string]any); ok {
		for _, n := range events {
			written += int(n.(float64))
		}
	}
	if written <= len(retained) {
		t.Fatalf("%d events were written, %d are retained: nothing was rotated out", written, len(retained))
	}
	outWait(t, 60*time.Second, "the TCP connection to end", func() bool { return tcp.NumConns() > 0 && tcp.AllEnded() })
	handed := outOutput(stopped, "udp", "handed_over")
	outWaitDatagrams(udp, handed, 20*time.Second)
	var hookBodies [][]byte
	for _, r := range hook.Accepted() {
		hookBodies = append(hookBodies, r.Body)
	}
	byID := outByID(retained)
	retainedRemote := outRemoteEvents(retained)
	for name, got := range map[string][][]byte{"tcp": tcp.LineBytes(), "udp": udp.Datagrams(), "webhook": hookBodies} {
		count := outCompareLines(t, name, got, byID, true)
		miss := len(outMissing(retainedRemote, count))
		switch name {
		case "udp":
			if miss > len(retainedRemote)/20 || len(got) < written*95/100 {
				t.Errorf("udp received %d of %d events and misses %d of the %d retained ones", len(got), written, miss, len(retainedRemote))
			}
		default:
			if len(got) != written || miss != 0 {
				t.Errorf("%s received %d of %d events and misses %d of the %d retained ones", name, len(got), written, miss, len(retainedRemote))
			}
		}
		if f := outOutput(stopped, name, "failed") + outOutput(stopped, name, "dropped_queue_full"); f != 0 {
			t.Errorf("%s: %d failed or dropped events", name, f)
		}
	}
	t.Logf("%d events written, %d retained in %d files after %d rotations; udp received %d of %d",
		written, len(retained), len(files), outOutput(stopped, "file", "rotations"), len(udp.Datagrams()), written)
}

// ----------------------------------------------------------------------------
// 12. Agent events reach the remote outputs

func TestOutAgentEventsReachRemotes(t *testing.T) {
	requireRoot(t)

	t.Run("all outputs healthy", func(t *testing.T) {
		tcp := outNewTCPServer(t, outTCPOpts{})
		udp := outNewUDPServer(t)
		hook := outNewHookServer(t)
		tk := outNewToken()
		a := outStart(t, outCfg{Token: tk, TCP: tcp.Addr, UDP: udp.Addr, Webhook: hook.URL, Health: "300ms"})
		a.waitEvents(30*time.Second, "three health events", func(evs []Ev) bool { return len(ofType(evs, "agent.health")) >= 3 })
		evs := outStopAndEvents(t, a)
		byID := outByID(evs)
		stopped := evs[len(evs)-1]

		outWait(t, 30*time.Second, "the TCP connection to be closed", func() bool { return tcp.NumConns() > 0 && tcp.AllEnded() })
		handed := outOutput(stopped, "udp", "handed_over")
		outWaitDatagrams(udp, handed, 20*time.Second)
		var hookBodies [][]byte
		for _, r := range hook.Accepted() {
			hookBodies = append(hookBodies, r.Body)
		}
		for name, got := range map[string][][]byte{"tcp": tcp.LineBytes(), "udp": udp.Datagrams(), "webhook": hookBodies} {
			count := outAssertIdentical(t, name, got, byID)
			types := map[string]int{}
			for id := range count {
				types[byID[id].Type()]++
			}
			for _, typ := range []string{"agent.started", "agent.ready", "agent.health"} {
				if types[typ] == 0 {
					t.Errorf("%s did not receive %s (got %v)", name, typ, types)
				}
			}
			// agent.stopped is stored locally only, after the queues were
			// flushed (DELIVERY.md): no output gets it.
			if types["agent.stopped"] != 0 || count[stopped.str("event_id")] != 0 {
				t.Errorf("%s received agent.stopped, which is stored locally only", name)
			}
			if got := types["agent.health"]; got != len(ofType(evs, "agent.health")) {
				t.Errorf("%s received %d health events, the log has %d", name, got, len(ofType(evs, "agent.health")))
			}
		}
		if ev := ofType(evs, "agent.started")[0]; len(ev.get("details.outputs").([]any)) != 4 {
			t.Errorf("agent.started lists the outputs %v, want file, tcp, udp, webhook", ev.get("details.outputs"))
		}
	})

	t.Run("failing output does not stop the others and shows in their health events", func(t *testing.T) {
		// A TCP target without a listener: every event fails after its retries.
		closed := outClosedAddr(t)
		udp := outNewUDPServer(t)
		hook := outNewHookServer(t)
		tk := outNewToken()
		a := outStart(t, outCfg{
			Token: tk,
			TCP:   closed, UDP: udp.Addr, Webhook: hook.URL, Health: "300ms",
			MaxRetries: outInt(1), ConnectTO: "1s", WriteTO: "1s", Shutdown: "2s",
		})
		var firstFailing Ev
		evs := outWaitHealth(t, a, 60*time.Second, "a health event that reports failed tcp events", func(h Ev) bool {
			if outOutput(h, "tcp", "failed") > 0 {
				firstFailing = h
				return true
			}
			return false
		})
		// Health events after that one still come, and the healthy outputs receive them.
		a.waitEvents(30*time.Second, "two more health events", func(evs []Ev) bool {
			n := 0
			for _, h := range ofType(evs, "agent.health") {
				if h.Seq() > firstFailing.Seq() {
					n++
				}
			}
			return n >= 2
		})
		evs = outStopAndEvents(t, a)
		byID := outByID(evs)

		handed := outOutput(evs[len(evs)-1], "udp", "handed_over")
		outWaitDatagrams(udp, handed, 20*time.Second)
		for name, bodies := range map[string][][]byte{"udp": udp.Datagrams(), "webhook": func() [][]byte {
			var b [][]byte
			for _, r := range hook.Accepted() {
				b = append(b, r.Body)
			}
			return b
		}()} {
			count := outAssertIdentical(t, name, bodies, byID)
			sawFailure := false
			for id := range count {
				h := byID[id]
				if h.Type() != "agent.health" {
					continue
				}
				// The health event as the healthy output received it carries the
				// counters of the failing one.
				var got Ev
				for _, line := range bodies {
					if outEventID(line) == id {
						got = parseEvents(line)[0]
					}
				}
				if outOutput(got, "tcp", "failed") > 0 || outOutput(got, "tcp", "dropped_queue_full") > 0 {
					sawFailure = true
				}
				if outOutput(got, "tcp", "handed_over") != 0 {
					t.Errorf("%s: a health event claims %d events handed over to the unreachable tcp target", name, outOutput(got, "tcp", "handed_over"))
				}
			}
			if !sawFailure {
				t.Errorf("%s: none of the received health events reports failed events of the tcp output", name)
			}
			var healthIDs int
			for id := range count {
				if byID[id].Type() == "agent.health" {
					healthIDs++
				}
			}
			if healthIDs < 3 {
				t.Errorf("%s received only %d health events while tcp was failing", name, healthIDs)
			}
		}
		if code := a.Stop(); code != 0 {
			t.Errorf("exit code %d", code)
		}
	})

	t.Run("SIGINT ends the run like SIGTERM", func(t *testing.T) {
		hook := outNewHookServer(t)
		tk := outNewToken()
		a := outStart(t, outCfg{Token: tk, Webhook: hook.URL, Health: "300ms"})
		a.waitEvents(30*time.Second, "a health event", func(evs []Ev) bool { return len(ofType(evs, "agent.health")) >= 1 })
		if err := a.cmd.Process.Signal(syscall.SIGINT); err != nil {
			t.Fatal(err)
		}
		select {
		case <-a.done:
		case <-time.After(30 * time.Second):
			t.Fatal("the agent did not stop after SIGINT")
		}
		if a.exit != 0 {
			t.Fatalf("exit code %d after SIGINT, want 0:\n%s", a.exit, a.stderr.String())
		}
		evs := a.Events()
		stopped := evs[len(evs)-1]
		if stopped.Type() != "agent.stopped" || stopped.str("details.reason") != "signal" {
			t.Fatalf("the last line is %s (reason %q), want agent.stopped after a signal", stopped.Type(), stopped.str("details.reason"))
		}
		var bodies [][]byte
		for _, r := range hook.Accepted() {
			bodies = append(bodies, r.Body)
		}
		count := outAssertIdentical(t, "webhook", bodies, outByID(evs))
		if miss := outMissing(outRemoteEvents(evs), count); len(miss) > 0 {
			t.Errorf("the queue was not flushed on SIGINT: %d events missing, e.g. %v", len(miss), miss[:min(3, len(miss))])
		}
	})
}

// outClosedAddr returns a loopback address on which nothing listens.
func outClosedAddr(t *testing.T) string {
	t.Helper()
	srv := outNewTCPServer(t, outTCPOpts{})
	addr := srv.Addr
	srv.Close()
	return addr
}

// ----------------------------------------------------------------------------
// 13. UDP: the socket is re-established after the target was down (the UDP requirements)

func TestOutUDPReconnect(t *testing.T) {
	requireRoot(t)
	outEnsureLoopback(t)
	// Reserve an address on which nothing listens yet. The kernel answers the
	// first datagram with ICMP port unreachable, so the next send on the
	// connected socket fails; the agent counts that as failed, drops the events
	// of the backoff period (counted too) and creates a new socket later.
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := l.LocalAddr().(*net.UDPAddr)
	l.Close()
	tk := outNewToken()
	a := outStart(t, outCfg{Token: tk, UDP: addr.String(), Health: "300ms", ConnectTO: "1s", WriteTO: "1s", Shutdown: "5s"})
	evs := outWaitHealth(t, a, 60*time.Second, "failed udp events while the target is down", func(h Ev) bool {
		return outOutput(h, "udp", "failed") >= 1
	})
	if got := outOutput(evs[len(evs)-1], "udp", "retries"); got != 0 {
		t.Errorf("udp retries %d: UDP never retransmits", got)
	}
	select {
	case <-a.done:
		t.Fatalf("the agent exited because the udp target is down:\n%s", a.stderr.String())
	default:
	}

	// The receiver appears on the same address; no restart of the agent.
	recv := outNewUDPServerAt(t, addr)
	outWait(t, 60*time.Second, "datagrams after the receiver came up", func() bool { return recv.Count() >= 3 })
	evs = outStopAndEvents(t, a)
	stopped := evs[len(evs)-1]
	outWaitDatagrams(recv, outOutput(stopped, "udp", "handed_over"), 10*time.Second)
	count := outAssertIdentical(t, "udp", recv.Datagrams(), outByID(evs))
	if len(count) < 3 {
		t.Errorf("only %d events arrived after the target came back", len(count))
	}
	if outOutput(stopped, "udp", "failed") < 1 || outOutput(stopped, "udp", "handed_over") < 3 {
		t.Errorf("udp counters in agent.stopped: %v", stopped.get("details.outputs.udp"))
	}
	t.Logf("udp: failed %d during the outage, handed over %d afterwards, %d received", outOutput(stopped, "udp", "failed"), outOutput(stopped, "udp", "handed_over"), len(count))
}

// ----------------------------------------------------------------------------
// 14. IPv6 literals as targets (for example [2001:db8::10]:9000)

func TestOutIPv6Targets(t *testing.T) {
	requireRoot(t)
	outEnsureLoopback(t)
	if ln, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 loopback in this environment: %v", err)
	} else {
		c, derr := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		ln.Close()
		if derr != nil {
			t.Skipf("the IPv6 loopback is not usable: %v", derr)
		}
		c.Close()
	}
	tcp := outNewTCPServer(t, outTCPOpts{Listen: "[::1]:0"})
	udp := outNewUDPServerAt(t, &net.UDPAddr{IP: net.IPv6loopback})
	hook := outNewHookServerAt(t, "[::1]:0")
	d := newProgDir(t)
	tk := outNewToken()
	a := outStart(t, outCfg{Token: tk, TCP: tcp.Addr, UDP: udp.Addr, Webhook: hook.URL + "/hook", Health: "500ms"})
	if !strings.Contains(tcp.Addr, "[::1]") || !strings.Contains(hook.URL, "[::1]") {
		t.Fatalf("test setup: %s %s", tcp.Addr, hook.URL)
	}

	root := d.outBurst(tk.Root(), 30, 0, 1)
	outBurstDone(t, root, 10*time.Minute)
	outWaitAfterExit(t, a, root.PID, 60*time.Second)
	evs := outStopAndEvents(t, a)
	stopped := evs[len(evs)-1]
	byID := outByID(evs)
	want := outRemoteEvents(evs)

	outWait(t, 30*time.Second, "the TCP connection to end", func() bool { return tcp.NumConns() > 0 && tcp.AllEnded() })
	outWaitDatagrams(udp, outOutput(stopped, "udp", "handed_over"), 20*time.Second)
	var hookBodies [][]byte
	for _, r := range hook.Accepted() {
		hookBodies = append(hookBodies, r.Body)
	}
	for name, got := range map[string][][]byte{"tcp": tcp.LineBytes(), "udp": udp.Datagrams(), "webhook": hookBodies} {
		count := outAssertIdentical(t, name, got, byID)
		if lost := len(outMissing(want, count)); (name == "udp" && lost > len(want)/20) || (name != "udp" && lost > 0) {
			t.Errorf("%s over IPv6 did not receive %d of %d events", name, lost, len(want))
		}
		if f := outOutput(stopped, name, "failed"); f != 0 {
			t.Errorf("%s: %d failed events", name, f)
		}
	}
}
