//go:build linux

package app

import "testing"

func capSet(caps ...int) func(int) bool {
	return func(c int) bool {
		for _, x := range caps {
			if x == c {
				return true
			}
		}
		return false
	}
}

func statusOf(checks []Check, name string) (Status, bool) {
	for _, c := range checks {
		if c.Name == name {
			return c.Status, true
		}
	}
	return "", false
}

func TestPrivilegeChecksJudgeTheEffectiveSetNotRoot(t *testing.T) {
	for _, tc := range []struct {
		name     string
		euid     int
		caps     []int
		kill     bool
		priv     Status
		wantKill Status // empty when kill is false
	}{
		{"root with the full set", 0, []int{capSysAdmin, capBPF, capPerfmon, capKill}, true, StatusOK, StatusOK},
		{"the service's set", 0, []int{capBPF, capPerfmon, capKill}, true, StatusOK, StatusOK},
		{"root without CAP_KILL (restricted bounding set)", 0, []int{capBPF, capPerfmon}, true, StatusOK, StatusWarn},
		{"root without any capability", 0, nil, true, StatusFail, StatusWarn},
		{"unprivileged user", 1000, nil, false, StatusFail, ""},
		{"user with file capabilities", 1000, []int{capBPF, capPerfmon, capKill}, true, StatusOK, StatusOK},
		{"kill not requested", 0, []int{capBPF, capPerfmon}, false, StatusOK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checks := privilegeChecksFor(tc.euid, capSet(tc.caps...), tc.kill)
			if got, ok := statusOf(checks, "privileges"); !ok || got != tc.priv {
				t.Errorf("privileges = %v (present %v), want %v: %+v", got, ok, tc.priv, checks)
			}
			got, ok := statusOf(checks, "CAP_KILL")
			if tc.kill != ok {
				t.Fatalf("CAP_KILL check present = %v, want %v", ok, tc.kill)
			}
			if tc.kill && got != tc.wantKill {
				t.Errorf("CAP_KILL = %v, want %v: %+v", got, tc.wantKill, checks)
			}
		})
	}
}
