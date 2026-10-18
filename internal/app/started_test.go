package app

import (
	"strings"
	"testing"

	"github.com/Neo23x0/process-watcher/internal/config"
)

// agent.started reports the argument capture limits and the kill safeguards, so a reader of the log knows what a
// run could see and what its rules could reach.

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

func TestStartedReportsTheKillSafeguards(t *testing.T) {
	r := newRig(t, nil, func(c *config.Config) {
		c.Kill = config.KillConfig{Enabled: true, DryRun: true, Fields: []string{"image"}, Strings: []string{"nginx"}, SpareRootImage: false}
	})
	r.start()
	ls := r.wait("ready", func(ls []line) bool { return count(ls, "agent.ready") == 1 })
	st := ls[0]
	if st.get("details.kill.spare_root_image") != false {
		t.Errorf("spare_root_image: %v", st.get("details.kill.spare_root_image"))
	}
	if w, _ := st.get("details.kill.warnings").([]any); len(w) != 1 || !strings.Contains(w[0].(string), `kill.strings[0] "nginx"`) {
		t.Errorf("warnings: %v", st.get("details.kill.warnings"))
	}
	r.stop()
	r.validateAll()
}

func TestStartedWithoutRulesHasNoWarnings(t *testing.T) {
	r := newRig(t, nil)
	r.start()
	ls := r.wait("ready", func(ls []line) bool { return count(ls, "agent.ready") == 1 })
	if w, _ := ls[0].get("details.kill.warnings").([]any); w == nil || len(w) != 0 {
		t.Errorf("warnings must be an empty list: %v", ls[0].get("details.kill.warnings"))
	}
	r.stop()
	r.validateAll()
}
