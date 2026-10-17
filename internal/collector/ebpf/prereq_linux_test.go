//go:build linux

package ebpf

import (
	"errors"
	"testing"

	"github.com/Neo23x0/process-watcher/internal/collector"
)

func TestParseLockdown(t *testing.T) {
	for in, want := range map[string]string{
		"[none] integrity confidentiality\n": "none",
		"none [integrity] confidentiality\n": "integrity",
		"none integrity [confidentiality]\n": "confidentiality",
		"":                                   "",
		"none integrity confidentiality":     "",
		"none [integrity":                    "",
	} {
		if got := parseLockdown(in); got != want {
			t.Errorf("parseLockdown(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLockdownConfidentialityIsNamed only runs on a kernel booted with
// lockdown=confidentiality (tests/vm: PW_VM_KARGS=lockdown=confidentiality,
// -test.run TestLockdown). The kernel then refuses the helpers that read kernel
// memory and the programs cannot load; the agent must say that, not blame the
// verifier or the permissions.
func TestLockdownConfidentialityIsNamed(t *testing.T) {
	if LockdownMode() != "confidentiality" {
		t.Skip("the kernel is not locked down in confidentiality mode")
	}
	requireRoot(t)
	if err := Preflight(); err != nil {
		var pe *collector.PrerequisiteError
		if !errors.As(err, &pe) || pe.Check != "kernel lockdown" {
			t.Fatalf("Preflight: %v, want a kernel lockdown diagnosis", err)
		}
	} else {
		t.Error("Preflight accepted a kernel in lockdown mode confidentiality")
	}
	_, err := New(collector.Options{RingBufferBytes: 1 << 20})
	var pe *collector.PrerequisiteError
	if !errors.As(err, &pe) || pe.Check != "kernel lockdown" {
		t.Fatalf("New: %v, want a kernel lockdown diagnosis", err)
	}
	t.Logf("diagnosis: %v", err)
}
