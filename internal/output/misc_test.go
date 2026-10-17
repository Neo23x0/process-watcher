package output

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestBackoffDelay(t *testing.T) {
	s := time.Second
	t.Run("production defaults double up to the cap", func(t *testing.T) {
		b := newBackoff(Hooks{BackoffJitter: -1})
		for i, want := range []time.Duration{1 * s, 2 * s, 4 * s, 8 * s, 16 * s, 30 * s, 30 * s, 30 * s} {
			if got := b.delay(i + 1); got != want {
				t.Errorf("delay(%d) = %s, want %s", i+1, got, want)
			}
		}
		if got := b.delay(1 << 30); got != 30*s {
			t.Errorf("delay(huge) = %s, want the cap", got)
		}
	})
	t.Run("custom bounds", func(t *testing.T) {
		b := newBackoff(Hooks{BackoffBase: time.Millisecond, BackoffMax: 3 * time.Millisecond, BackoffJitter: -1})
		for i, want := range []time.Duration{1, 2, 3, 3} {
			if got := b.delay(i + 1); got != want*time.Millisecond {
				t.Errorf("delay(%d) = %s, want %dms", i+1, got, want)
			}
		}
		if b := newBackoff(Hooks{BackoffBase: 5 * s, BackoffMax: s, BackoffJitter: -1}); b.delay(3) != 5*s {
			t.Error("a cap below the base must not shrink the base")
		}
	})
	t.Run("jitter is plus or minus 20 percent and never above the cap", func(t *testing.T) {
		b := newBackoff(Hooks{})
		draw := 0.0
		b.rnd = func() float64 { return draw }
		for _, tc := range []struct {
			n    int
			draw float64
			want time.Duration
		}{
			{1, 0.0, 800 * time.Millisecond},
			{1, 0.5, 1 * s},
			{3, 0.0, 3200 * time.Millisecond},
			{3, 0.5, 4 * s},
			{6, 0.0, 24 * s}, // capped value minus 20%
			{6, 0.5, 30 * s},
			{6, 0.999999, 30 * s}, // never above the cap
		} {
			draw = tc.draw
			if got := b.delay(tc.n); got != tc.want {
				t.Errorf("delay(%d) with draw %v = %s, want %s", tc.n, tc.draw, got, tc.want)
			}
		}
		// With the real random source every value stays inside the band.
		real := newBackoff(Hooks{})
		for i := 0; i < 2000; i++ {
			if d := real.delay(2); d < 1600*time.Millisecond || d > 2400*time.Millisecond {
				t.Fatalf("delay(2) = %s outside 2s +-20%%", d)
			}
			if d := real.delay(9); d < 24*s || d > 30*s {
				t.Fatalf("delay(9) = %s outside [24s, 30s]", d)
			}
		}
	})
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) time.Time { return now.Add(d) }
	tests := []struct {
		name   string
		value  string
		want   time.Duration
		wantOK bool
	}{
		{"empty", "", 0, false},
		{"zero seconds", "0", 0, true},
		{"seconds", "5", 5 * time.Second, true},
		{"seconds with spaces", " 7 ", 7 * time.Second, true},
		{"exactly the cap", "60", 60 * time.Second, true},
		{"above the cap", "61", 60 * time.Second, true},
		{"absurdly large", "99999999999999999999999999", 60 * time.Second, true},
		{"negative", "-5", 0, false},
		{"fraction", "1.5", 0, false},
		{"garbage", "soon", 0, false},
		{"HTTP date", at(10 * time.Second).Format(http.TimeFormat), 10 * time.Second, true},
		{"RFC 850 date", at(10 * time.Second).Format(time.RFC850), 10 * time.Second, true},
		{"asctime date", at(10 * time.Second).Format(time.ANSIC), 10 * time.Second, true},
		{"date in the past", at(-time.Hour).Format(http.TimeFormat), 0, true},
		{"date far in the future", at(24 * time.Hour).Format(http.TimeFormat), 60 * time.Second, true},
		{"malformed date", "Fri, 99 Foo 2026 12:00:10 GMT", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseRetryAfter(tc.value, now)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("parseRetryAfter(%q) = %s, %v; want %s, %v", tc.value, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestRedactURL(t *testing.T) {
	tests := []struct{ raw, want string }{
		{"https://host.example/path?token=abc&x=y", "https://host.example/...?token=REDACTED&x=REDACTED"},
		{"http://host.example:8080/", "http://host.example:8080/"},
		{"http://host.example", "http://host.example"},
		{"https://hooks.example/services/T000/B000/XXXXSECRET", "https://hooks.example/..."},
		{"HTTPS://Host.Example/x?secretword", "https://Host.Example/...?REDACTED"},
		{"http://host.example/?a=1&&b", "http://host.example/?a=REDACTED&REDACTED&REDACTED"},
		{"http://[::1]:9000/x?k=v", "http://[::1]:9000/...?k=REDACTED"},
		{"http://host.example/x?k=", "http://host.example/...?k=REDACTED"},
	}
	for _, tc := range tests {
		u, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := redactURL(u); got != tc.want {
			t.Errorf("redactURL(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestScrubber(t *testing.T) {
	t.Run("removes secrets, longest first", func(t *testing.T) {
		scrub := newScrubber([]string{"", "abc", "abcdef"})
		if got := scrub("x abcdef y abc z"); got != "x [redacted] y [redacted] z" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("neutralizes control characters and invalid UTF-8", func(t *testing.T) {
		got := newScrubber(nil)("a\nb\x00c\x1b[31m\xff\xfe")
		if strings.ContainsAny(got, "\n\x00\x1b") || !utf8.ValidString(got) {
			t.Errorf("got %q", got)
		}
	})
	t.Run("is bounded on a rune boundary", func(t *testing.T) {
		got := newScrubber(nil)(strings.Repeat("é", 1000))
		if len(got) > lastErrorMax+3 || !utf8.ValidString(got) || !strings.HasSuffix(got, "...") {
			t.Errorf("len %d, valid %v", len(got), utf8.ValidString(got))
		}
		if short := newScrubber(nil)("short"); short != "short" {
			t.Errorf("short message changed: %q", short)
		}
	})
}

func countLogLines(logs *syncBuffer) int { return strings.Count(logs.String(), "msg=") }

func TestErrReporterRateLimitsLogLines(t *testing.T) {
	clk := newFakeClock()
	logger, logs := captureLogger()
	rep := newErrReporter(logger, clk.Now, newScrubber([]string{"SECRET"}))
	fail := func() { rep.failure(errors.New("dial tcp: connection refused SECRET")) }

	for i := 0; i < 100; i++ { // a burst of errors within ten seconds
		fail()
		clk.Advance(100 * time.Millisecond)
	}
	if n := countLogLines(logs); n != 1 {
		t.Fatalf("%d log lines for the burst, want only the first error:\n%s", n, logs)
	}
	clk.Advance(60 * time.Second)
	fail()
	if n := countLogLines(logs); n != 2 || !strings.Contains(logs.String(), "suppressed_since_last_report=99") {
		t.Fatalf("want one summary line after 60s:\n%s", logs)
	}
	if strings.Contains(rep.lastError(), "SECRET") || !strings.Contains(rep.lastError(), "connection refused") {
		t.Errorf("lastError = %q", rep.lastError())
	}

	rep.success() // the incident ended: one recovery line
	if n := countLogLines(logs); n != 3 || !strings.Contains(logs.String(), "recovered") {
		t.Fatalf("want a recovery line:\n%s", logs)
	}
	rep.success() // healthy again: nothing more
	if n := countLogLines(logs); n != 3 {
		t.Fatalf("steady success logged:\n%s", logs)
	}

	// A flapping target: errors and recoveries inside the window stay quiet.
	clk.Advance(time.Second)
	fail()
	rep.success()
	if n := countLogLines(logs); n != 3 {
		t.Fatalf("flapping inside the rate limit window was logged:\n%s", logs)
	}
	// After the window the next incident is logged again.
	clk.Advance(61 * time.Second)
	fail()
	rep.success()
	if n := countLogLines(logs); n != 5 {
		t.Fatalf("want a new error and its recovery after the window, got %d lines:\n%s", n, logs)
	}
	if strings.Contains(logs.String(), "SECRET") {
		t.Error("secret in the log")
	}
}

func TestWriteFullAndHeaderValues(t *testing.T) {
	if err := writeFull(zeroWriter{}, []byte("x")); !errors.Is(err, io.ErrShortWrite) {
		t.Errorf("writeFull with a stuck writer = %v, want ErrShortWrite", err)
	}
	if err := writeFull(zeroWriter{}, nil); err != nil {
		t.Errorf("writeFull of nothing = %v", err)
	}
	for s, want := range map[string]bool{
		"": true, "plain": true, "with space": true, "tab\tok": true, "éé": true,
		"cr\r": false, "lf\n": false, "nul\x00": false, "del\x7f": false,
	} {
		if got := validHeaderValue(s); got != want {
			t.Errorf("validHeaderValue(%q) = %v, want %v", s, got, want)
		}
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }
