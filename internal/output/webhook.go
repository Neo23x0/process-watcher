package output

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultWebhookTimeout = 10 * time.Second
	// maxResponseBody is how much of a response body is read (to allow
	// connection reuse) before it is discarded and closed.
	maxResponseBody = 4 << 10
	// maxRetryAfter caps a server supplied Retry-After.
	maxRetryAfter = 60 * time.Second
)

// WebhookOptions configures the webhook output. Zero values select
// QueueSize 10000, ConnectTimeout and WriteTimeout 5s and Timeout 10s;
// MaxRetries 0 means a single attempt per event.
type WebhookOptions struct {
	// URL must use http or https and must not contain credentials or a
	// fragment. It may contain secrets (query, path); they are redacted in
	// every log line and error.
	URL string
	// Token, if not empty, is sent as "Authorization: Bearer <token>". It is
	// never logged or put into an error.
	Token string
	// UserAgentVersion completes "User-Agent: process-watcher/<version>"
	// (default "dev").
	UserAgentVersion string

	QueueSize      int
	MaxRetries     int
	ConnectTimeout time.Duration // dial plus TLS handshake
	WriteTimeout   time.Duration // per write of the request on the connection
	Timeout        time.Duration // whole request including the response header
	Logger         *slog.Logger

	Hooks Hooks
}

// webhookRemote POSTs each event as one request. Redirects are not followed.
type webhookRemote struct {
	*engine
	target    string // contains secrets: only used to build requests
	redacted  string
	client    *http.Client
	closeIdle func()
	userAgent string
	auth      string // "Bearer <token>" or ""
	timeout   time.Duration
}

var _ Remote = (*webhookRemote)(nil)

// NewWebhook starts a webhook output. It does not contact the network.
func NewWebhook(opts WebhookOptions) (Remote, error) {
	u, err := parseWebhookURL(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("webhook output: %w", err)
	}
	if strings.IndexFunc(opts.Token, isControl) >= 0 {
		// Never echo the token; a trailing newline from a file or an
		// environment variable is the usual cause.
		return nil, errors.New("webhook output: token contains a control character (e.g. a trailing newline)")
	}
	version := opts.UserAgentVersion
	if version == "" {
		version = "dev"
	}
	if !validHeaderValue(version) {
		return nil, errors.New("webhook output: user agent version contains a control character")
	}
	qs, err := queueSizeOrDefault(opts.QueueSize)
	if err != nil {
		return nil, fmt.Errorf("webhook output: %w", err)
	}
	if err := checkRetries(opts.MaxRetries); err != nil {
		return nil, fmt.Errorf("webhook output: %w", err)
	}
	ct, err := durationOrDefault("connect timeout", opts.ConnectTimeout, defaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("webhook output: %w", err)
	}
	wt, err := durationOrDefault("write timeout", opts.WriteTimeout, defaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("webhook output: %w", err)
	}
	timeout, err := durationOrDefault("timeout", opts.Timeout, defaultWebhookTimeout)
	if err != nil {
		return nil, fmt.Errorf("webhook output: %w", err)
	}

	w := &webhookRemote{
		target:    u.String(),
		redacted:  redactURL(u),
		userAgent: "process-watcher/" + version,
		timeout:   timeout,
	}
	if opts.Token != "" {
		w.auth = "Bearer " + opts.Token
	}
	rt := opts.Hooks.Transport
	if rt == nil {
		tr := newHTTPTransport(ct, wt, opts.Hooks.RootCAs, opts.Hooks.Dial)
		rt, w.closeIdle = tr, tr.CloseIdleConnections
	} else if c, ok := rt.(interface{ CloseIdleConnections() }); ok {
		w.closeIdle = c.CloseIdleConnections
	}
	w.client = &http.Client{
		Transport: rt,
		// A 3xx is a final answer, never followed.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	w.engine = newEngine(engineConfig{
		name: "webhook", queueSize: qs, maxRetries: opts.MaxRetries, logger: opts.Logger, hooks: opts.Hooks,
		secrets: webhookSecrets(u, opts.Token),
	})
	w.start(func(it item) { w.deliver(it, w.attempt) }, w.cleanup)
	return w, nil
}

func (w *webhookRemote) Enqueue(eventID string, line []byte) bool { return w.enqueue(eventID, line) }

func (w *webhookRemote) cleanup() {
	if w.closeIdle != nil {
		w.closeIdle()
	}
}

// attempt performs one POST and classifies the answer.
func (w *webhookRemote) attempt(ctx context.Context, it item) attemptResult {
	if !validHeaderValue(it.id) {
		return attemptResult{err: errors.New("event id is not a valid header value")}
	}
	rctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, w.target, bytes.NewReader(it.line))
	if err != nil {
		return attemptResult{err: w.redactErr(err)}
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("User-Agent", w.userAgent)
	req.Header["X-Event-ID"] = []string{it.id} // exact spelling on the wire
	if w.auth != "" {
		req.Header.Set("Authorization", w.auth)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return attemptResult{err: w.redactErr(err), retryable: true}
	}
	defer resp.Body.Close()
	// Read a little so the connection can be reused, discard the rest.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
	return w.classify(resp)
}

// classify maps an HTTP status to success, retry or final failure.
func (w *webhookRemote) classify(resp *http.Response) attemptResult {
	code := resp.StatusCode
	switch {
	case code >= 200 && code < 300:
		return attemptResult{}
	case code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500:
		res := attemptResult{err: fmt.Errorf("webhook %s answered HTTP %d", w.redacted, code), retryable: true}
		if code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable {
			if d, ok := parseRetryAfter(resp.Header.Get("Retry-After"), w.now()); ok {
				res.minWait = d
			}
		}
		return res
	case code >= 300 && code < 400:
		return attemptResult{err: fmt.Errorf("webhook %s answered HTTP %d: redirects are not followed", w.redacted, code)}
	}
	return attemptResult{err: fmt.Errorf("webhook %s answered HTTP %d", w.redacted, code)}
}

// redactErr replaces the URL that net/http embeds in its errors.
func (w *webhookRemote) redactErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return &url.Error{Op: ue.Op, URL: w.redacted, Err: ue.Err}
	}
	return err
}

// parseWebhookURL accepts absolute http(s) URLs without credentials or
// fragment. Errors never quote the URL, since it may contain secrets.
func parseWebhookURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("URL is empty")
	}
	if strings.Contains(raw, "#") {
		return nil, errors.New("URL must not contain a fragment")
	}
	u, err := url.Parse(raw)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return nil, fmt.Errorf("URL is invalid: %v", ue.Err)
		}
		return nil, errors.New("URL is invalid")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return nil, fmt.Errorf("URL scheme %q is not supported (use http or https)", u.Scheme)
	}
	if u.Opaque != "" || u.Hostname() == "" {
		return nil, errors.New("URL has no host")
	}
	if u.User != nil {
		return nil, errors.New("URL must not contain credentials; use the token setting")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.ParseUint(p, 10, 16); err != nil || n == 0 {
			return nil, errors.New("URL has an invalid port")
		}
	}
	return u, nil
}

// webhookSecrets lists strings that must never appear in diagnostics.
func webhookSecrets(u *url.URL, token string) []string {
	secrets := []string{token}
	if full := u.String(); full != redactURL(u) { // else there is nothing to hide
		secrets = append(secrets, full)
	}
	if u.RawQuery != "" {
		secrets = append(secrets, u.RawQuery)
		for _, vals := range u.Query() {
			for _, v := range vals {
				if len(v) >= 4 { // shorter values would garble ordinary messages
					secrets = append(secrets, v)
				}
			}
		}
	}
	return secrets
}

// newHTTPTransport builds a dedicated transport: normal certificate
// verification (system pool unless roots is set), TLS 1.2+, bounded dial,
// handshake and write times, no compression.
func newHTTPTransport(connectTimeout, writeTimeout time.Duration, roots *x509.CertPool,
	dial func(ctx context.Context, network, address string) (net.Conn, error)) *http.Transport {
	if dial == nil {
		dial = (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext
	}
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &writeTimeoutConn{Conn: c, timeout: writeTimeout}, nil
		},
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   connectTimeout,
		DisableCompression:    true,
		MaxIdleConns:          1,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// writeTimeoutConn bounds every write on the connection.
type writeTimeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (c *writeTimeoutConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(p)
}

// parseRetryAfter understands both forms of RFC 9110: delay seconds and an
// HTTP date. The result is capped at maxRetryAfter; a date in the past yields
// 0. ok is false if the value is absent or malformed.
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if isDigits(v) {
		secs, err := strconv.ParseUint(v, 10, 63)
		if err != nil || secs > uint64(maxRetryAfter/time.Second) {
			return maxRetryAfter, true // valid but huge
		}
		return time.Duration(secs) * time.Second, true
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return 0, false
	}
	return min(max(t.Sub(now), 0), maxRetryAfter), true
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// validHeaderValue reports whether s can be sent as a header value.
func validHeaderValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if b := s[i]; b != '\t' && (b < 0x20 || b == 0x7f) {
			return false
		}
	}
	return true
}
