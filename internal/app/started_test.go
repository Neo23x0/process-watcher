package app

import (
	"testing"

	"github.com/Neo23x0/process-watcher/internal/config"
)

// agent.started reports the argument capture limits, so a reader of the log knows what a run could see.

func TestStartedReportsTheCaptureLimits(t *testing.T) {
	r := newRig(t, nil, func(c *config.Config) {
		c.Capture.Argv = true
		c.Capture.ArgvMaxBytes = 16383
		c.Capture.ArgvMaxArgs = 64
	})
	r.start()
	ls := r.wait("ready", func(ls []line) bool { return count(ls, "agent.ready") == 1 })
	st := ls[0]
	if st.get("details.capture_argv_limits.max_bytes") != float64(16383) || st.get("details.capture_argv_limits.max_args") != float64(64) {
		t.Errorf("limits: %v", st.m["details"])
	}
	// The collector was opened with the limits.
	if o := r.col.Options(); o.ArgLimits.MaxBytes != 16383 || o.ArgLimits.MaxArgs != 64 || !o.CaptureArgs {
		t.Errorf("collector options %+v", o)
	}
	r.stop()
	r.validateAll()
}

func TestStartedWithoutCaptureHasNoLimits(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	ls := r.wait("ready", func(ls []line) bool { return count(ls, "agent.ready") == 1 })
	if v, present := ls[0].m["details"].(map[string]any)["capture_argv_limits"]; !present || v != nil {
		t.Errorf("capture_argv_limits must be null without capture.argv: %v", v)
	}
	r.stop()
	r.validateAll()
}
