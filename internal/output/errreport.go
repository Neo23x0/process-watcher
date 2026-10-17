package output

import (
	"log/slog"
	"sync"
	"time"
)

// errorLogInterval is the minimum time between two log lines about transport
// errors of one output.
const errorLogInterval = 60 * time.Second

// errReporter keeps the last error of an output (scrubbed, for
// RemoteStats.LastError) and rate limits log lines: the first error is logged
// at once, further errors only count up and are summarized in at most one line
// per interval. A recovery line follows the end of an incident that was
// logged. Failures never become events themselves.
type errReporter struct {
	log      *slog.Logger
	now      func() time.Time
	scrub    func(string) string
	interval time.Duration

	mu            sync.Mutex
	last          string
	suppressed    int64 // errors since the last emitted line
	logged        bool
	lastLine      time.Time
	failing       bool // errors since the last success
	announced     bool // a line was emitted during the current incident
	recovered     bool
	lastRecovered time.Time
}

func newErrReporter(log *slog.Logger, now func() time.Time, scrub func(string) string) *errReporter {
	return &errReporter{log: log, now: now, scrub: scrub, interval: errorLogInterval}
}

// failure records err and logs it unless the rate limit applies.
func (r *errReporter) failure(err error) {
	msg := r.scrub(err.Error())
	now := r.now()

	r.mu.Lock()
	r.last = msg
	r.failing = true
	if r.logged && now.Sub(r.lastLine) < r.interval {
		r.suppressed++
		r.mu.Unlock()
		return
	}
	suppressed := r.suppressed
	r.suppressed = 0
	r.logged, r.announced, r.lastLine = true, true, now
	r.mu.Unlock()

	if suppressed > 0 {
		r.log.Warn("remote delivery still failing",
			"error", msg, "suppressed_since_last_report", suppressed)
		return
	}
	r.log.Warn("remote delivery error", "error", msg)
}

// success ends an incident, logging its end if its start was logged.
func (r *errReporter) success() {
	r.mu.Lock()
	if !r.failing {
		r.mu.Unlock()
		return
	}
	now := r.now()
	r.failing = false
	announce := r.announced && (!r.recovered || now.Sub(r.lastRecovered) >= r.interval)
	r.announced = false
	suppressed := r.suppressed
	r.suppressed = 0
	if announce {
		r.recovered, r.lastRecovered = true, now
	}
	r.mu.Unlock()

	if announce {
		r.log.Info("remote delivery recovered", "suppressed_errors", suppressed)
	}
}

// lastError returns the most recent scrubbed error ("" if none occurred).
func (r *errReporter) lastError() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}
