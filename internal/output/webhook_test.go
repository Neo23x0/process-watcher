package output

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newWebhook(t *testing.T, opts WebhookOptions) *webhookRemote {
	t.Helper()
	opts.Hooks = fast(opts.Hooks)
	r, err := NewWebhook(opts)
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	cleanupShutdown(t, r)
	return r.(*webhookRemote)
}

type reply struct {
	status int
	header map[string]string
}

// replies answers request n with replies[n-1]; the last reply repeats.
func replies(rs ...reply) func(w http.ResponseWriter, r *http.Request, n int) {
	return func(w http.ResponseWriter, r *http.Request, n int) {
		rp := rs[min(n, len(rs))-1]
		for k, v := range rp.header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(rp.status)
	}
}

func TestWebhookStatusHandling(t *testing.T) {
	clk := newFakeClock()
	inFiveSeconds := clk.Now().Add(5 * time.Second).UTC().Format(http.TimeFormat)
	inThePast := clk.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	ms := time.Millisecond

	tests := []struct {
		name         string
		replies      []reply
		maxRetries   int
		wantAttempts int
		wantHanded   int64
		wantFailed   int64
		wantWaits    []time.Duration // nil: don't check; backoff is 1ms, 2ms, 4ms ...
	}{
		{"200 accepted", []reply{{200, nil}}, 5, 1, 1, 0, []time.Duration{}},
		{"204 accepted", []reply{{204, nil}}, 5, 1, 1, 0, []time.Duration{}},
		{"201 accepted", []reply{{201, nil}}, 5, 1, 1, 0, []time.Duration{}},
		{"429 with Retry-After seconds is a lower bound", []reply{{429, map[string]string{"Retry-After": "2"}}, {200, nil}}, 5, 2, 1, 0, []time.Duration{2 * time.Second}},
		{"429 without Retry-After uses the backoff", []reply{{429, nil}, {200, nil}}, 5, 2, 1, 0, []time.Duration{ms}},
		{"429 with a huge Retry-After is capped at 60s", []reply{{429, map[string]string{"Retry-After": "3600"}}, {200, nil}}, 5, 2, 1, 0, []time.Duration{60 * time.Second}},
		{"503 with Retry-After HTTP date", []reply{{503, map[string]string{"Retry-After": inFiveSeconds}}, {200, nil}}, 5, 2, 1, 0, []time.Duration{5 * time.Second}},
		{"503 with a Retry-After date in the past", []reply{{503, map[string]string{"Retry-After": inThePast}}, {200, nil}}, 5, 2, 1, 0, []time.Duration{ms}},
		{"429 with an invalid Retry-After", []reply{{429, map[string]string{"Retry-After": "soon"}}, {200, nil}}, 5, 2, 1, 0, []time.Duration{ms}},
		{"Retry-After is ignored on other statuses", []reply{{500, map[string]string{"Retry-After": "30"}}, {200, nil}}, 5, 2, 1, 0, []time.Duration{ms}},
		{"persistent 503 with Retry-After", []reply{{503, map[string]string{"Retry-After": "1"}}}, 2, 3, 0, 1, []time.Duration{time.Second, time.Second}},
		{"500 then 200", []reply{{500, nil}, {200, nil}}, 5, 2, 1, 0, []time.Duration{ms}},
		{"persistent 500 exhausts the retries", []reply{{500, nil}}, 3, 4, 0, 1, []time.Duration{ms, 2 * ms, 4 * ms}},
		{"persistent 500 with max_retries 0", []reply{{500, nil}}, 0, 1, 0, 1, []time.Duration{}},
		{"502 is retried", []reply{{502, nil}}, 1, 2, 0, 1, nil},
		{"504 is retried", []reply{{504, nil}}, 1, 2, 0, 1, nil},
		{"408 is retried", []reply{{408, nil}}, 1, 2, 0, 1, nil},
		{"400 is final", []reply{{400, nil}}, 5, 1, 0, 1, []time.Duration{}},
		{"401 is final", []reply{{401, nil}}, 5, 1, 0, 1, []time.Duration{}},
		{"403 is final", []reply{{403, nil}}, 5, 1, 0, 1, []time.Duration{}},
		{"404 is final", []reply{{404, nil}}, 5, 1, 0, 1, []time.Duration{}},
		{"413 is final", []reply{{413, nil}}, 5, 1, 0, 1, []time.Duration{}},
		{"422 is final", []reply{{422, nil}}, 5, 1, 0, 1, []time.Duration{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newHookServer(t, false, replies(tc.replies...))
			sleeps := &sleepRecorder{}
			r := newWebhook(t, WebhookOptions{URL: srv.URL + "/hook", MaxRetries: tc.maxRetries,
				Hooks: Hooks{Sleep: sleeps.Sleep, Now: clk.Now}})
			line := makeLine("evt-status", 200)
			r.Enqueue("evt-status", line)
			waitFor(t, "the event to be settled", func() bool {
				st := r.Stats()
				return st.HandedOver+st.Failed == 1
			})

			if n := srv.Count(); n != tc.wantAttempts {
				t.Errorf("requests = %d, want %d", n, tc.wantAttempts)
			}
			st := r.Stats()
			if st.HandedOver != tc.wantHanded || st.Failed != tc.wantFailed || st.Retries != int64(tc.wantAttempts-1) {
				t.Errorf("stats = %+v, want handed %d failed %d retries %d", st, tc.wantHanded, tc.wantFailed, tc.wantAttempts-1)
			}
			if tc.wantWaits != nil {
				if got := sleeps.all(); fmt.Sprint(got) != fmt.Sprint(tc.wantWaits) {
					t.Errorf("waits = %v, want %v", got, tc.wantWaits)
				}
			}
			// Every attempt carries the same id and identical bytes.
			for i, req := range srv.Requests() {
				if !bytes.Equal(req.Body, line) || req.Header.Get("X-Event-ID") != "evt-status" {
					t.Errorf("attempt %d differs from the first (id %q, %d body bytes)", i+1, req.Header.Get("X-Event-ID"), len(req.Body))
				}
			}
		})
	}
}

func TestWebhookDoesNotFollowRedirects(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			target := newHookServer(t, false, nil)
			redirector := newHookServer(t, false, func(w http.ResponseWriter, r *http.Request, n int) {
				http.Redirect(w, r, target.URL+"/landing?token=LOCATIONSECRET", status)
			})
			r := newWebhook(t, WebhookOptions{URL: redirector.URL + "/hook", MaxRetries: 5})
			r.Enqueue("evt-redirect", makeLine("evt-redirect", 200))
			waitFor(t, "the event to be given up", func() bool { return r.Stats().Failed == 1 })

			if target.Count() != 0 {
				t.Fatal("the redirect target received a request")
			}
			if redirector.Count() != 1 {
				t.Errorf("requests to the redirecting server = %d, want 1 (a 3xx is final)", redirector.Count())
			}
			st := r.Stats()
			if st.Retries != 0 || st.HandedOver != 0 {
				t.Errorf("stats = %+v", st)
			}
			if !strings.Contains(st.LastError, "redirects are not followed") || strings.Contains(st.LastError, "LOCATIONSECRET") {
				t.Errorf("LastError = %q", st.LastError)
			}
		})
	}
}

func TestWebhookTimeoutIsRetried(t *testing.T) {
	srv := newHookServer(t, false, func(w http.ResponseWriter, r *http.Request, n int) {
		select { // a receiver that never answers
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})
	r := newWebhook(t, WebhookOptions{URL: srv.URL, Timeout: 100 * time.Millisecond, MaxRetries: 2})
	r.Enqueue("evt-timeout", makeLine("evt-timeout", 200))
	waitFor(t, "the event to be given up", func() bool { return r.Stats().Failed == 1 })

	if n := srv.Count(); n != 3 {
		t.Errorf("requests = %d, want 3 (max_retries 2 means at most 3 attempts)", n)
	}
	st := r.Stats()
	if st.Retries != 2 || !strings.Contains(st.LastError, "event dropped after 3 attempts") {
		t.Errorf("stats = %+v", st)
	}
	// A URL without path or query has nothing to hide: the target stays visible.
	if !strings.Contains(st.LastError, srv.URL) {
		t.Errorf("LastError %q does not identify the target %s", st.LastError, srv.URL)
	}
}

func TestWebhookNetworkErrorIsRetried(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	addr := ln.Addr().String()
	ln.Close() // nothing listens any more: connection refused

	r := newWebhook(t, WebhookOptions{URL: "http://" + addr + "/hook", MaxRetries: 2})
	r.Enqueue("evt-net", makeLine("evt-net", 200))
	waitFor(t, "the event to be given up", func() bool { return r.Stats().Failed == 1 })
	if st := r.Stats(); st.Retries != 2 || st.HandedOver != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestWebhookRequestFormat(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		version   string
		wantAuth  string
		wantAgent string
	}{
		{"with token", "s3cret-token", "1.2.3", "Bearer s3cret-token", "process-watcher/1.2.3"},
		{"without token", "", "1.2.3", "", "process-watcher/1.2.3"},
		{"default version", "", "", "", "process-watcher/dev"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newHookServer(t, false, nil)
			r := newWebhook(t, WebhookOptions{URL: srv.URL + "/hooks/processes?x=1", Token: tc.token, UserAgentVersion: tc.version})
			line := makeLine("evt-format", 321)
			r.Enqueue("evt-format", line)
			waitFor(t, "delivery", func() bool { return r.Stats().HandedOver == 1 })

			reqs := srv.Requests()
			if len(reqs) != 1 {
				t.Fatalf("requests = %d", len(reqs))
			}
			req := reqs[0]
			if req.Method != http.MethodPost || req.URI != "/hooks/processes?x=1" {
				t.Errorf("request = %s %s", req.Method, req.URI)
			}
			for header, want := range map[string]string{
				"Content-Type":  "application/x-ndjson",
				"User-Agent":    tc.wantAgent,
				"X-Event-ID":    "evt-format",
				"Authorization": tc.wantAuth,
			} {
				if got := req.Header.Get(header); got != want {
					t.Errorf("%s = %q, want %q", header, got, want)
				}
			}
			if !bytes.Equal(req.Body, line) {
				t.Error("body is not the exact JSONL line")
			}
			if r.Name() != "webhook" {
				t.Errorf("Name = %q", r.Name())
			}
		})
	}
}

// The header names must reach the wire exactly as specified.
func TestWebhookHeaderSpellingOnTheWire(t *testing.T) {
	raw := make(chan []byte, 1)
	sink := newTCPSink(t, nil, func(idx int, c net.Conn, sc *sinkConn) {
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 1024)
		for !bytes.Contains(buf, []byte("\r\n\r\n")) {
			n, err := c.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if err != nil {
				return
			}
		}
		select {
		case raw <- buf:
		default:
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	})
	r := newWebhook(t, WebhookOptions{URL: "http://" + sink.Addr() + "/h"})
	r.Enqueue("evt-wire", makeLine("evt-wire", 150))
	select {
	case buf := <-raw:
		if !bytes.Contains(buf, []byte("\r\nX-Event-ID: evt-wire\r\n")) {
			t.Errorf("X-Event-ID is not on the wire as written in the spec:\n%s", buf)
		}
	case <-time.After(testWait):
		t.Fatal("no request seen")
	}
}

func TestWebhookHTTPS(t *testing.T) {
	srv := newHookServer(t, true, nil)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	t.Run("trusted certificate", func(t *testing.T) {
		r := newWebhook(t, WebhookOptions{URL: srv.URL + "/hook", Hooks: Hooks{RootCAs: pool}})
		r.Enqueue("evt-https", makeLine("evt-https", 200))
		waitFor(t, "delivery", func() bool { return r.Stats().HandedOver == 1 })
	})
	t.Run("untrusted certificate is never bypassed", func(t *testing.T) {
		before := srv.Count()
		r := newWebhook(t, WebhookOptions{URL: srv.URL + "/hook", MaxRetries: 1}) // system pool
		r.Enqueue("evt-untrusted", makeLine("evt-untrusted", 200))
		waitFor(t, "the event to be given up", func() bool { return r.Stats().Failed == 1 })
		if srv.Count() != before {
			t.Fatal("a request reached a server with an untrusted certificate")
		}
		if st := r.Stats(); !strings.Contains(st.LastError, "certificate") {
			t.Errorf("LastError = %q", st.LastError)
		}
	})
}

func TestWebhookSecretsNeverLeak(t *testing.T) {
	const token = "tok-9f8e7d6c5b4a3210"
	secrets := []string{token, "PATHSECRET", "QUERYSECRET", "ROOMSECRET", "api_key=QUERYSECRET"}
	check := func(t *testing.T, what, text string) {
		t.Helper()
		for _, s := range secrets {
			if strings.Contains(text, s) {
				t.Errorf("%s contains the secret %q:\n%s", what, s, text)
			}
		}
	}

	t.Run("network error", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		must(t, err)
		addr := ln.Addr().String()
		ln.Close()
		logger, logs := captureLogger()
		r := newWebhook(t, WebhookOptions{
			URL:   "http://" + addr + "/services/T0001/PATHSECRET?api_key=QUERYSECRET&room=ROOMSECRET",
			Token: token, MaxRetries: 1, Logger: logger,
		})
		r.Enqueue("evt-secret", makeLine("evt-secret", 200))
		waitFor(t, "the event to be given up", func() bool { return r.Stats().Failed == 1 })
		shutdownRemote(t, r)

		st := r.Stats()
		check(t, "LastError", st.LastError)
		check(t, "log output", logs.String())
		if !strings.Contains(st.LastError, addr) || !strings.Contains(st.LastError, "api_key=REDACTED") {
			t.Errorf("LastError %q should still identify the target (host and parameter names)", st.LastError)
		}
	})

	t.Run("HTTP error status", func(t *testing.T) {
		srv := newHookServer(t, false, func(w http.ResponseWriter, r *http.Request, n int) {
			w.WriteHeader(http.StatusUnauthorized)
			// A receiver that echoes the credentials must not leak them either.
			_, _ = io.WriteString(w, "bad token "+r.Header.Get("Authorization")+" for "+r.RequestURI)
		})
		logger, logs := captureLogger()
		r := newWebhook(t, WebhookOptions{
			URL:   srv.URL + "/services/T0001/PATHSECRET?api_key=QUERYSECRET&room=ROOMSECRET",
			Token: token, Logger: logger,
		})
		r.Enqueue("evt-secret", makeLine("evt-secret", 200))
		waitFor(t, "the event to be given up", func() bool { return r.Stats().Failed == 1 })
		shutdownRemote(t, r)
		check(t, "LastError", r.Stats().LastError)
		check(t, "log output", logs.String())
	})
}

func TestWebhookRejectsInvalidEventIDWithoutRequest(t *testing.T) {
	srv := newHookServer(t, false, nil)
	r := newWebhook(t, WebhookOptions{URL: srv.URL, MaxRetries: 3})
	r.Enqueue("bad\r\nInjected: header", makeLine("evt", 100))
	waitFor(t, "the event to be given up", func() bool { return r.Stats().Failed == 1 })
	if srv.Count() != 0 || r.Stats().Retries != 0 {
		t.Errorf("requests = %d, retries = %d; an invalid id must fail at once", srv.Count(), r.Stats().Retries)
	}
}

// Only a small, fixed part of a response body is read; the rest is discarded
// by closing the connection.
func TestWebhookReadsOnlyBoundedResponseBody(t *testing.T) {
	const total = 64 << 20
	var written atomic.Int64
	handlerDone := make(chan struct{})
	srv := newHookServer(t, false, func(w http.ResponseWriter, r *http.Request, n int) {
		defer close(handlerDone)
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 32<<10)
		for written.Load() < total {
			m, err := w.Write(chunk)
			written.Add(int64(m))
			if err != nil {
				return
			}
		}
	})
	r := newWebhook(t, WebhookOptions{URL: srv.URL, Timeout: 30 * time.Second})
	r.Enqueue("evt-body", makeLine("evt-body", 200))
	waitFor(t, "delivery", func() bool { return r.Stats().HandedOver == 1 })
	select {
	case <-handlerDone:
	case <-time.After(testWait):
		t.Fatal("the server kept sending: the response body was not abandoned")
	}
	if written.Load() >= total {
		t.Fatalf("server delivered the whole %d byte body", total)
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type trackedBody struct {
	read   atomic.Int64
	closed atomic.Bool
}

func (b *trackedBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	b.read.Add(int64(len(p)))
	return len(p), nil
}

func (b *trackedBody) Close() error { b.closed.Store(true); return nil }

func TestWebhookAlwaysClosesResponseBody(t *testing.T) {
	for _, status := range []int{200, 204, 302, 400, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			body := &trackedBody{}
			rt := rtFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: http.Header{}, Body: body, Request: req}, nil
			})
			r := newWebhook(t, WebhookOptions{URL: "http://collector.example.test/hook", Hooks: Hooks{Transport: rt}})
			r.Enqueue("evt-close", makeLine("evt-close", 100))
			waitFor(t, "the event to be settled", func() bool { st := r.Stats(); return st.HandedOver+st.Failed == 1 })
			if !body.closed.Load() {
				t.Error("response body was not closed")
			}
			if n := body.read.Load(); n > 4096 {
				t.Errorf("read %d bytes of the response body, want at most 4096", n)
			}
		})
	}
}

// A receiver that stops reading must trip the write timeout, long before the
// overall request timeout.
func TestWebhookWriteTimeout(t *testing.T) {
	release := make(chan struct{})
	sink := newTCPSink(t, nil, func(idx int, c net.Conn, sc *sinkConn) { <-release })
	t.Cleanup(func() { close(release) })

	r := newWebhook(t, WebhookOptions{URL: "http://" + sink.Addr() + "/hook",
		Timeout: 60 * time.Second, WriteTimeout: 150 * time.Millisecond})
	start := time.Now()
	r.Enqueue("evt-slow", makeLine("evt-slow", 32<<20)) // far beyond the socket buffers
	waitFor(t, "the event to be given up", func() bool { return r.Stats().Failed == 1 })
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("took %s; the write timeout did not apply", d)
	}
	if st := r.Stats(); !strings.Contains(st.LastError, "timeout") {
		t.Errorf("LastError = %q, want a timeout", st.LastError)
	}
}

func TestNewWebhookValidation(t *testing.T) {
	bad := []struct {
		name string
		opts WebhookOptions
	}{
		{"empty URL", WebhookOptions{}},
		{"unsupported scheme", WebhookOptions{URL: "ftp://collector.example.net/hook?token=SECRETVALUE"}},
		{"no scheme", WebhookOptions{URL: "collector.example.net/hook?token=SECRETVALUE"}},
		{"no host", WebhookOptions{URL: "https:///hook?token=SECRETVALUE"}},
		{"credentials in the URL", WebhookOptions{URL: "https://user:PASSWORDVALUE@collector.example.net/hook"}},
		{"user without password", WebhookOptions{URL: "https://USERVALUE@collector.example.net/hook"}},
		{"fragment", WebhookOptions{URL: "https://collector.example.net/hook?token=SECRETVALUE#frag"}},
		{"empty fragment", WebhookOptions{URL: "https://collector.example.net/hook?token=SECRETVALUE#"}},
		{"opaque URL", WebhookOptions{URL: "https:collector.example.net?token=SECRETVALUE"}},
		{"invalid port", WebhookOptions{URL: "https://collector.example.net:99999/hook?token=SECRETVALUE"}},
		{"unparseable", WebhookOptions{URL: "https://[::1/hook?token=SECRETVALUE"}},
		{"control character in the token", WebhookOptions{URL: "https://collector.example.net/hook", Token: "TOKENVALUE\n"}},
		{"control character in the version", WebhookOptions{URL: "https://collector.example.net/hook", UserAgentVersion: "1.0\r\nX: y"}},
		{"negative queue", WebhookOptions{URL: "https://collector.example.net/hook", QueueSize: -1}},
		{"negative retries", WebhookOptions{URL: "https://collector.example.net/hook", MaxRetries: -1}},
		{"negative timeout", WebhookOptions{URL: "https://collector.example.net/hook", Timeout: -time.Second}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewWebhook(tc.opts)
			if err == nil {
				r.Shutdown(context.Background())
				t.Fatal("NewWebhook succeeded")
			}
			for _, secret := range []string{"SECRETVALUE", "PASSWORDVALUE", "USERVALUE", "TOKENVALUE"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error %q reveals %q", err, secret)
				}
			}
		})
	}
	for _, good := range []string{
		"https://collector.example.net/hooks/processes",
		"http://192.0.2.10:8080/in",
		"HTTPS://Collector.Example.net/x?a=b&c=d",
		"http://[2001:db8::10]:8080/in",
	} {
		r, err := NewWebhook(WebhookOptions{URL: good})
		if err != nil {
			t.Errorf("NewWebhook(%q): %v", good, err)
			continue
		}
		if st := r.Stats(); st.QueueCap != 10000 {
			t.Errorf("default queue size = %d", st.QueueCap)
		}
		shutdownRemote(t, r)
	}
}

func TestWebhookRedirectPolicyAndTransportSettings(t *testing.T) {
	r := newWebhook(t, WebhookOptions{URL: "https://collector.example.net/hook", ConnectTimeout: 3 * time.Second})
	if r.client.CheckRedirect == nil {
		t.Fatal("no redirect policy")
	}
	if err := r.client.CheckRedirect(&http.Request{URL: &url.URL{}}, nil); err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
	tr, ok := r.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T", r.client.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion < 0x0303 {
		t.Errorf("TLS client config = %+v", tr.TLSClientConfig)
	}
	if tr.TLSClientConfig.RootCAs != nil {
		t.Error("custom roots set without a hook: the system pool must be used")
	}
	if tr.TLSHandshakeTimeout != 3*time.Second {
		t.Errorf("TLSHandshakeTimeout = %s", tr.TLSHandshakeTimeout)
	}
}
