//go:build linux

package integration

// PHP deployment tests. They use the topologies of real PHP deployments (a
// service master with workers, workers that start shells, interpreters and
// helpers) with harmless programs only: no vulnerability, no exploit payload.
// The process names carry a unique prefix so that no other process of the
// test host is selected; matching is by substring, so the prefix changes
// nothing about what is tested.
//
// What they establish is documented in docs/php.md; tests/php/ checks the same
// shapes against the real nginx, Apache and PHP of a distribution.

import (
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// phpShellImage is what /bin/sh is called in events: the base name of its
// target (dash on Debian and Ubuntu, bash elsewhere).
func phpShellImage(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skipf("no /bin/sh: %v", err)
	}
	return filepath.Base(p)
}

func argvIs(e Ev, want ...string) bool {
	got := e.argv()
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// execsWith returns the exec events whose argument vector satisfies pred.
func execsWith(evs []Ev, pred func(Ev) bool) []Ev {
	return filterEv(evs, func(e Ev) bool { return e.Type() == "process.exec" && pred(e) })
}

func execOfImage(evs []Ev, image string) []Ev {
	return execsWith(evs, func(e Ev) bool { return e.Image() == image })
}

// shellExecs are the exec events of a shell started with the given command string.
func shellExecs(evs []Ev, shell, command string) []Ev {
	return execsWith(evs, func(e Ev) bool {
		a := e.argv()
		return e.Image() == shell && len(a) == 4 && a[1] == "-c" && a[2] == "--" && a[3] == command
	})
}

func hasProcessEventOf(evs []Ev, pid int) bool {
	return len(ofPID(evs, pid)) > 0
}

// processEventCount counts the process.* events: what an observer sees of the processes.
func processEventCount(evs []Ev) int {
	return len(filterEv(evs, func(e Ev) bool { return strings.HasPrefix(e.Type(), "process.") }))
}

func (e Ev) parentPID() int { return e.num("parent.pid") }
func (e Ev) execIndex() int { return e.num("details.exec_index") }
func (e Ev) complete() bool { b, _ := e.get("process.argv_complete").(bool); return b }

// lineageComplete is lineage.complete: the chain from the root is backed by observed relations.
func (e Ev) lineageComplete() bool { b, _ := e.get("lineage.complete").(bool); return b }

// missingFields is the number of data_quality.missing_fields.
func (e Ev) missingFields() int {
	arr, _ := e.get("data_quality.missing_fields").([]any)
	return len(arr)
}

// --- 1. watch targets ----------------------------------------------------------------------

func TestPHPWatchTargetsFollowTheExecutionModel(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	sh := phpShellImage(t)
	d := newProgDir(t)

	// NGINX and PHP-FPM are independent services: PHP does not run in an NGINX worker.
	web := d.startFleet(n.Nginx, 2, 0)
	fpm := d.startFleet(n.FPM, 2, 0)
	// Apache with mod_php executes PHP in its own workers.
	mod := d.startFleet(n.Apache, 2, 0)

	t.Run("a watch on nginx alone does not see what PHP-FPM runs", func(t *testing.T) {
		a := startAgent(t, agentCfg{Watch: []string{n.Nginx}, CaptureArgv: true})
		fpm.Request(0, "shell", "echo via-php-fpm")
		web.Request(0, "shell", "echo via-nginx")
		evs := a.waitEvents(killScale(20*time.Second), "the shell of the nginx worker", func(evs []Ev) bool {
			return len(shellExecs(evs, sh, "echo via-nginx")) == 1
		})
		fpm.waitLines("done op=shell", 1, killScale(10*time.Second))
		time.Sleep(killScale(300 * time.Millisecond))
		evs = a.Events()
		if got := shellExecs(evs, sh, "echo via-php-fpm"); len(got) != 0 {
			t.Fatalf("the shell started by a PHP-FPM worker was observed through an nginx watch: %v", got[0].Line)
		}
		if hasProcessEventOf(evs, fpm.PID) || len(execOfImage(evs, n.FPM)) != 0 {
			t.Errorf("PHP-FPM is not a descendant of nginx, yet it appears in the events")
		}
		// The nginx tree itself is covered, with nginx as the root.
		own := shellExecs(evs, sh, "echo via-nginx")[0]
		if own.RootPID() != web.PID || own.Role() != "descendant" {
			t.Errorf("root %d role %s, want nginx master %d", own.RootPID(), own.Role(), web.PID)
		}
	})

	t.Run("a watch on php-fpm sees the workers and what they start", func(t *testing.T) {
		a := startAgent(t, agentCfg{Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true})
		fpm.Request(1, "shell", "uname -s; id -u")
		evs := a.waitEvents(killScale(20*time.Second), "uname and id below the shell", func(evs []Ev) bool {
			return len(execOfImage(evs, "uname")) == 1 && len(execOfImage(evs, "id")) == 1
		})
		// The master is the root; its workers, discovered at start, are descendants.
		var rootEv *Ev
		for _, e := range ofType(evs, "process.discovered") {
			if e.PID() == fpm.PID {
				e := e
				rootEv = &e
			}
		}
		if rootEv == nil || rootEv.Role() != "root" || rootEv.Image() != n.FPM {
			t.Fatalf("the master %d must be discovered as root with the versioned image %q: %v", fpm.PID, n.FPM, rootEv)
		}
		for _, w := range fpm.WorkerPIDs() {
			var found bool
			for _, e := range ofPID(evs, w) {
				if e.Role() == "descendant" && e.Depth() == 1 && e.RootPID() == fpm.PID {
					found = true
				}
			}
			if !found {
				t.Errorf("worker %d was not discovered as a depth 1 descendant of the master", w)
			}
		}
		for _, img := range []string{"uname", "id"} {
			e := execOfImage(evs, img)[0]
			if e.RootPID() != fpm.PID || e.Depth() != 3 {
				t.Errorf("%s: root %d depth %d, want root %d depth 3 (master, worker, shell, program)", img, e.RootPID(), e.Depth(), fpm.PID)
			}
		}
		// Neither nginx nor the Apache workers are involved.
		if hasProcessEventOf(evs, web.PID) || hasProcessEventOf(evs, mod.PID) {
			t.Error("a php-fpm watch selected the web servers")
		}
	})

	t.Run("a watch on apache2 sees PHP running inside the Apache workers", func(t *testing.T) {
		a := startAgent(t, agentCfg{Watch: []string{n.Apache}, CaptureArgv: true})
		mod.Request(0, "shell", "echo via-mod-php")
		evs := a.waitEvents(killScale(20*time.Second), "the shell of the Apache worker", func(evs []Ev) bool {
			return len(shellExecs(evs, sh, "echo via-mod-php")) == 1
		})
		e := shellExecs(evs, sh, "echo via-mod-php")[0]
		if e.RootPID() != mod.PID || e.Depth() != 2 {
			t.Errorf("root %d depth %d, want the Apache master %d at depth 2 (master, worker, shell)", e.RootPID(), e.Depth(), mod.PID)
		}
	})
}

// "php" selects every PHP executable: FPM, CGI and the CLI. The version suffix tells
// them apart, and exclusions only filter what is reported.
func TestPHPWatchSubstringsSelectTheExpectedExecutables(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	d := newProgDir(t)
	fpm := d.startFleet(n.FPM, 1, 0)
	plain := d.startFleet(n.FPMPlain, 1, 0)
	cgi := d.startFleet(n.CGI, 1, 0)
	cli := d.startFleet(n.CLI, 1, 0)
	p := n.Tok.Prefix() + "-"

	roots := func(t *testing.T, watch ...string) map[int]string {
		t.Helper()
		a := startAgent(t, agentCfg{Watch: watch, CaptureArgv: true})
		out := map[int]string{}
		for _, e := range ofType(a.Events(), "process.discovered") {
			if e.Role() == "root" {
				out[e.PID()] = e.Image()
			}
		}
		a.Stop()
		return out
	}
	want := func(t *testing.T, got map[int]string, pids ...int) {
		t.Helper()
		if len(got) != len(pids) {
			t.Fatalf("roots %v, want the processes %v", got, pids)
		}
		for _, pid := range pids {
			if _, ok := got[pid]; !ok {
				t.Fatalf("roots %v, want the processes %v", got, pids)
			}
		}
	}
	t.Run("php-fpm selects versioned and unversioned FPM masters and nothing else", func(t *testing.T) {
		want(t, roots(t, p+"php-fpm"), fpm.PID, plain.PID)
	})
	t.Run("php-cgi selects the CGI masters", func(t *testing.T) {
		want(t, roots(t, p+"php-cgi"), cgi.PID)
	})
	t.Run("the versioned CLI name does not select FPM or CGI", func(t *testing.T) {
		want(t, roots(t, p+"php8.4"), cli.PID)
	})
	t.Run("the generic php selects every PHP executable", func(t *testing.T) {
		want(t, roots(t, p+"php"), fpm.PID, plain.PID, cgi.PID, cli.PID)
	})
}

// --- 2. command lines ----------------------------------------------------------------------

func TestPHPSpawnedProgramsKeepTheirCommandLines(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	sh := phpShellImage(t)
	d := newProgDir(t, n.Python, n.CLI)
	fpm := d.startFleet(n.FPM, 2, 0)
	a := startAgent(t, agentCfg{Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true})
	workers := fpm.WorkerPIDs()
	py, php := filepath.Join(d.dir, n.Python), filepath.Join(d.dir, n.CLI)

	// A shell command, a direct launch without a shell, interpreters with inline code, awkward arguments.
	fpm.Request(0, "shell", "uname -s; id -u")
	fpm.Request(0, "direct", "/bin/true", "", "a b", "\"q\" 's'", "line1\nline2", "tab\tx")
	fpm.Request(0, "shell", py+" -c 'print(40+2)'")
	fpm.Request(0, "shell", php+" -r 'echo 6*7;'")
	fpm.Launch(1, n.Python, "php-echo", "-c", "print(1)")
	fpm.waitLines("done op=", 5, killScale(20*time.Second))
	evs := a.waitEvents(killScale(20*time.Second), "all spawned programs", func(evs []Ev) bool {
		return len(execOfImage(evs, "true")) == 1 && len(execOfImage(evs, n.Python)) == 2 && len(execOfImage(evs, n.CLI)) == 1 &&
			len(execOfImage(evs, "uname")) == 1 && len(execOfImage(evs, "id")) == 1
	})

	t.Run("a shell keeps its complete command string as one element", func(t *testing.T) {
		if got := shellExecs(evs, sh, "uname -s; id -u"); len(got) != 1 {
			t.Fatalf("want one shell with argv [sh -c -- <command>], got %d", len(got))
		} else if e := got[0]; e.parentPID() != workers[0] || e.RootPID() != fpm.PID || e.Depth() != 2 || !e.complete() {
			t.Errorf("parent %d root %d depth %d complete=%v", e.parentPID(), e.RootPID(), e.Depth(), e.complete())
		}
		for img, args := range map[string][]string{"uname": {"uname", "-s"}, "id": {"id", "-u"}} {
			e := execOfImage(evs, img)[0]
			if !argvIs(e, args...) || e.Depth() != 3 || e.RootPID() != fpm.PID {
				t.Errorf("%s: argv %q depth %d root %d", img, e.argv(), e.Depth(), e.RootPID())
			}
		}
	})
	t.Run("a direct launch without a shell is attributed to the worker", func(t *testing.T) {
		e := execOfImage(evs, "true")[0]
		if e.parentPID() != workers[0] || e.Depth() != 2 || e.RootPID() != fpm.PID {
			t.Errorf("parent %d depth %d root %d; want the worker %d directly above, no shell in between", e.parentPID(), e.Depth(), e.RootPID(), workers[0])
		}
		// Empty arguments, spaces, quotes, a newline and a tab survive as separate elements.
		if !argvIs(e, "/bin/true", "", "a b", "\"q\" 's'", "line1\nline2", "tab\tx") {
			t.Errorf("argv %q", e.argv())
		}
		if !e.complete() {
			t.Error("argv_complete must be true")
		}
	})
	t.Run("interpreters with inline code keep it", func(t *testing.T) {
		var seen []string
		for _, e := range execOfImage(evs, n.Python) {
			a := e.argv()
			seen = append(seen, strings.Join(a[1:], "|"))
			if len(a) != 3 || a[1] != "-c" || (a[2] != "print(40+2)" && a[2] != "print(1)") {
				t.Errorf("python argv %q", a)
			}
		}
		if len(seen) != 2 {
			t.Errorf("seen %v", seen)
		}
		if e := execOfImage(evs, n.CLI)[0]; !argvIs(e, php, "-r", "echo 6*7;") {
			t.Errorf("php -r argv %q", e.argv())
		}
	})
	t.Run("the chain of an interpreter started through a shell can be rebuilt", func(t *testing.T) {
		e := execOfImage(evs, n.CLI)[0]
		anc, _ := e.get("lineage.ancestors").([]any)
		if len(anc) != 3 || e.Depth() != 3 || anc[0] != e.str("root.process_id") || anc[2] != e.str("parent.process_id") {
			t.Errorf("ancestors %v depth %d", anc, e.Depth())
		}
		// master -> worker -> shell -> php: every link has its own event with its arguments.
		shell := shellExecs(evs, sh, php+" -r 'echo 6*7;'")
		if len(shell) != 1 || shell[0].ID() != e.str("parent.process_id") {
			t.Errorf("the parent reference of php must name the shell instance: %v", e.str("parent.process_id"))
		}
	})
}

// A worker that replaces its own executable keeps its PID and identity; every exec has its own event
// with its own arguments.
func TestPHPWorkerReplacingItsExecutableIsOneProcessWithTwoExecs(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	d := newProgDir(t, n.CLI)
	fpm := d.startFleet(n.FPM, 1, 0)
	a := startAgent(t, agentCfg{Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true})
	worker := fpm.WorkerPIDs()[0]
	php := filepath.Join(d.dir, n.CLI)

	fpm.Request(0, "exec", php, "-r", "echo 1;")
	evs := a.waitEvents(killScale(20*time.Second), "the exec of the worker", func(evs []Ev) bool {
		return len(execOfImage(evs, n.CLI)) == 1
	})
	e := execOfImage(evs, n.CLI)[0]
	if e.PID() != worker || e.execIndex() != 1 || e.str("details.previous_image") != n.FPM || e.Role() != "descendant" || e.RootPID() != fpm.PID {
		t.Fatalf("pid %d exec_index %d previous %q role %s root %d; want the worker %d replaced in place",
			e.PID(), e.execIndex(), e.str("details.previous_image"), e.Role(), e.RootPID(), worker)
	}
	if !argvIs(e, php, "-r", "echo 1;") {
		t.Errorf("argv of the new image: %q", e.argv())
	}
	// The master replaces the worker that ended, a new instance with its own identity.
	fpm.waitLines("worker started", 2, killScale(10*time.Second))
	evs = a.Events()
	var ids = map[string]bool{}
	for _, ev := range ofPID(evs, worker) {
		ids[ev.ID()] = true
	}
	if len(ids) != 1 {
		t.Errorf("the worker has %d identities, want exactly one for the whole in-place exec", len(ids))
	}
}

// --- 3. capture limits ---------------------------------------------------------------------

// For a PHP shell_exec, the shell is started as `sh -c -- <command>`: three short arguments use 9 bytes of
// the capture, and the command has to fit into what is left of 4096 bytes together with its NUL.
func TestPHPInlineCommandsAroundTheDefaultLimit(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	sh := phpShellImage(t)
	d := newProgDir(t)
	fpm := d.startFleet(n.FPM, 1, 0)
	a := startAgent(t, agentCfg{Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true})
	if lim := ofType(a.Events(), "agent.started")[0].get("details.capture_argv_limits"); lim == nil {
		t.Fatal("agent.started must report the capture limits")
	}

	cmdOf := func(length int) string { return "echo " + strings.Repeat("A", length-5) }
	const room = 4096 - len("sh\x00-c\x00--\x00") - 1 // the longest command that is captured completely
	if room != 4086 {
		t.Fatalf("room %d", room)
	}
	for _, length := range []int{100, room - 1, room, room + 1, 6000} {
		cmd := cmdOf(length)
		fpm.Request(0, "shell", cmd)
	}
	fpm.waitLines("done op=shell", 5, killScale(30*time.Second))
	evs := a.waitEvents(killScale(20*time.Second), "all five shells", func(evs []Ev) bool {
		return len(execsWith(evs, func(e Ev) bool {
			a := e.argv()
			return e.Image() == sh && len(a) >= 3 && a[0] == "sh" && a[1] == "-c" && a[2] == "--"
		})) >= 5
	})
	for _, length := range []int{100, room - 1, room} {
		got := shellExecs(evs, sh, cmdOf(length))
		if len(got) != 1 || !got[0].complete() || got[0].get("process.argv_capture") != nil {
			t.Errorf("a command of %d bytes must be captured completely: %d events", length, len(got))
		}
	}
	// One byte more and the argument is dropped from the list: the shell is still seen, but its command is
	// not in argv. The text is kept separately, marked as partial, with the totals.
	for _, length := range []int{room + 1, 6000} {
		cmd := cmdOf(length)
		var cut []Ev
		for _, e := range execsWith(evs, func(e Ev) bool { return e.Image() == sh && len(e.argv()) == 3 && !e.complete() }) {
			if int(e.num("process.argv_capture.total_bytes")) == 9+length+1 {
				cut = append(cut, e)
			}
		}
		if len(cut) != 1 {
			t.Fatalf("a command of %d bytes: %d incomplete exec events with the matching total", length, len(cut))
		}
		e := cut[0]
		if !argvIs(e, "sh", "-c", "--") || e.get("process.argv_capture.partial.index") != float64(3) ||
			e.num("process.argv_capture.argc") != 4 || e.num("process.argv_capture.captured_args") != 3 ||
			e.num("process.argv_capture.captured_bytes") != 4096 || e.num("process.argv_capture.limit_bytes") != 4096 ||
			e.num("process.argv_capture.limit_args") != 32 {
			t.Errorf("capture %v", e.get("process.argv_capture"))
		}
		prefix := e.str("process.argv_capture.partial.value")
		if !strings.HasPrefix(cmd, prefix) || len(prefix) != 4096-9 || e.num("process.argv_capture.partial.captured_bytes") != 4096-9 {
			t.Errorf("the partial command is %d bytes, want the first %d bytes of the command", len(prefix), 4096-9)
		}
		if !strings.Contains(strings.Join(truncatedFields(e), ","), "process.argv") {
			t.Errorf("data_quality.truncated_fields %v", truncatedFields(e))
		}
	}
}

// A short inline script is lost as well when it starts near the end of the capture: the options before it
// used the bytes. The partial argument keeps what was captured of it.
func TestPHPInlineCodeThatStartsNearTheEndOfTheCapture(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	d := newProgDir(t)
	fpm := d.startFleet(n.FPM, 1, 0)
	a := startAgent(t, agentCfg{Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true})
	filler := strings.Repeat("x", 4070)
	// raw: "/bin/true\0" (10) + filler and NUL (4071) + "-r\0" (3) + "echo 123456;\0" (13) = 4097 bytes
	fpm.Request(0, "direct", "/bin/true", filler, "-r", "echo 123456;")
	evs := a.waitEvents(killScale(20*time.Second), "the cut launch", func(evs []Ev) bool { return len(execOfImage(evs, "true")) == 1 })
	e := execOfImage(evs, "true")[0]
	if !argvIs(e, "/bin/true", filler, "-r") || e.complete() {
		t.Fatalf("argv has %d elements, complete=%v", len(e.argv()), e.complete())
	}
	if e.num("process.argv_capture.argc") != 4 || e.num("process.argv_capture.total_bytes") != 4097 ||
		e.str("process.argv_capture.partial.value") != "echo 123456;" || e.num("process.argv_capture.partial.index") != 3 {
		t.Errorf("capture %v", e.get("process.argv_capture"))
	}
}

func truncatedFields(e Ev) []string {
	arr, _ := e.get("data_quality.truncated_fields").([]any)
	var out []string
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func TestPHPConfigurableArgumentLimitsKeepLongInlineCommands(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	sh := phpShellImage(t)
	d := newProgDir(t)
	fpm := d.startFleet(n.FPM, 1, 0)
	a := startAgent(t, agentCfg{Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true, ArgvMaxBytes: 16383, ArgvMaxArgs: 64})
	started := ofType(a.Events(), "agent.started")[0]
	if started.num("details.capture_argv_limits.max_bytes") != 16383 || started.num("details.capture_argv_limits.max_args") != 64 {
		t.Errorf("agent.started reports %v", started.get("details.capture_argv_limits"))
	}

	long := "echo " + strings.Repeat("B", 12000)
	huge := "echo " + strings.Repeat("C", 40000)
	args := func(k int) []string {
		out := []string{"/bin/true"}
		for i := 0; i < k; i++ {
			out = append(out, "x")
		}
		return out
	}
	fpm.Request(0, "shell", long)
	fpm.Request(0, "shell", huge)
	fpm.Request(0, "direct", args(50)...) // 51 arguments: more than 32, within 64
	fpm.Request(0, "direct", args(100)...)
	fpm.waitLines("done op=", 4, killScale(30*time.Second))
	evs := a.waitEvents(killScale(20*time.Second), "the four starts", func(evs []Ev) bool {
		return len(execOfImage(evs, "true")) == 2 && len(shellExecs(evs, sh, long)) == 1 &&
			len(execsWith(evs, func(e Ev) bool { return e.Image() == sh && !e.complete() })) >= 1
	})

	if got := shellExecs(evs, sh, long); len(got) != 1 || !got[0].complete() {
		t.Fatalf("a 12000 byte command must be complete with a 16383 byte limit")
	}
	cut := execsWith(evs, func(e Ev) bool { return e.Image() == sh && !e.complete() })
	if len(cut) != 1 {
		t.Fatalf("%d incomplete shells", len(cut))
	}
	if e := cut[0]; e.num("process.argv_capture.total_bytes") != 9+len(huge)+1 || e.num("process.argv_capture.captured_bytes") != 16383 ||
		len(e.str("process.argv_capture.partial.value")) != 16383-9 || e.num("process.argv_capture.limit_bytes") != 16383 {
		t.Errorf("40 KB command: %v", e.get("process.argv_capture"))
	}
	trues := execOfImage(evs, "true")
	byLen := map[int]Ev{}
	for _, e := range trues {
		byLen[len(e.argv())] = e
	}
	if e, ok := byLen[51]; !ok || !e.complete() {
		t.Errorf("51 arguments must be complete with --capture-argv-max-args 64")
	}
	if e, ok := byLen[64]; !ok || e.complete() || e.num("process.argv_capture.argc") != 101 || e.num("process.argv_capture.limit_args") != 64 ||
		e.get("process.argv_capture.partial") != nil {
		t.Errorf("101 arguments: %v", e.get("process.argv_capture"))
	}
}

// The same limits through command line flags only.
func TestPHPArgumentLimitFlagsAreEquivalentToYAML(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	sh := phpShellImage(t)
	d := newProgDir(t)
	fpm := d.startFleet(n.FPM, 1, 0)
	dir := t.TempDir()
	a := &agent{t: t, dir: dir, LogPath: filepath.Join(dir, "events.jsonl"), stderr: &syncBuf{}}
	a.launch([]string{
		"--watch-image-contains", n.Tok.Prefix() + "-php-fpm", "--capture-argv=true",
		"--capture-argv-max-bytes", "16383", "--capture-argv-max-args", "64",
		"--log-file", a.LogPath, "--health-interval", "1s",
	}, nil)
	a.waitReady(20 * time.Second)
	cmd := "echo " + strings.Repeat("D", 9000)
	fpm.Request(0, "shell", cmd)
	evs := a.waitEvents(killScale(20*time.Second), "the long shell", func(evs []Ev) bool { return len(shellExecs(evs, sh, cmd)) == 1 })
	if !shellExecs(evs, sh, cmd)[0].complete() {
		t.Error("the flags did not reach the capture")
	}
	if got := ofType(evs, "agent.started")[0]; got.num("details.capture_argv_limits.max_bytes") != 16383 || got.num("details.capture_argv_limits.max_args") != 64 {
		t.Errorf("limits %v", got.get("details.capture_argv_limits"))
	}
}

// Limits outside what the kernel buffer holds are a configuration error, not a silent clamp.
func TestPHPArgumentLimitsOutsideTheSupportedRangeAreRefused(t *testing.T) {
	requireAgentBinary(t)
	for _, bad := range [][]string{
		{"--capture-argv-max-bytes", "16384"}, {"--capture-argv-max-bytes", "100"}, {"--capture-argv-max-args", "5000"}, {"--capture-argv-max-args", "0"},
	} {
		args := append([]string{"check-config", "--watch-image-contains", "x", "--capture-argv=true"}, bad...)
		out, code := runAgentCmd(t, args...)
		if code != 2 || !strings.Contains(out, "capture.argv_max_") {
			t.Errorf("%v: exit %d, output %q", bad, code, out)
		}
	}
	// A limit without capture is meaningless and refused as well.
	out, code := runAgentCmd(t, "check-config", "--watch-image-contains", "x", "--capture-argv-max-bytes", "8000")
	if code != 2 || !strings.Contains(out, "requires capture.argv: true") {
		t.Errorf("without capture: exit %d, output %q", code, out)
	}
}

func runAgentCmd(t *testing.T, args ...string) (string, int) {
	t.Helper()
	c := execCommand(agentBin, args...)
	out, _ := c.CombinedOutput()
	return string(out), c.ProcessState.ExitCode()
}

// --- 4. short-lived processes, exited parents, replacement, reload -----------------------------

func TestPHPShortLivedProgramsAndExitedParents(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	sh := phpShellImage(t)
	d := newProgDir(t)
	fpm := d.startFleet(n.FPM, 2, 0)
	a := startAgent(t, agentCfg{Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true})
	worker := fpm.WorkerPIDs()[0]

	// An intermediate shell that lives for a moment, started by a worker that then ends: the program the shell
	// starts later still belongs to the tree.
	fpm.Request(0, "shell-bg", "sleep 1; uname -r")
	fpm.waitLines("started op=shell-bg", 1, killScale(10*time.Second))
	shellPID := intAfter(fpm.Lines("started op=shell-bg")[0], "pid")
	fpm.Request(0, "exit")
	evs := a.waitEvents(killScale(30*time.Second), "uname after its parent worker ended", func(evs []Ev) bool {
		return len(execOfImage(evs, "uname")) == 1
	})
	u := execOfImage(evs, "uname")[0]
	if u.RootPID() != fpm.PID || u.parentPID() != shellPID || !u.lineageComplete() || u.Depth() != 3 {
		t.Errorf("uname: root %d parent %d (shell %d) depth %d", u.RootPID(), u.parentPID(), shellPID, u.Depth())
	}
	// The worker ended before its grandchildren did, and its exit is in the log.
	if got := kinds(ofPID(evs, worker)); !strings.Contains(got, "exit") {
		t.Errorf("worker events [%s]", got)
	}
	// the shell ends right after its last program; its exit record may still be on its way
	evs = a.waitEvents(killScale(10*time.Second), "the exit of the shell", func(evs []Ev) bool { return exitOf(evs, shellPID) != nil })
	if x := exitOf(evs, shellPID); x.Image() != sh {
		t.Errorf("the shell's exit event names image %q", x.Image())
	}

	// Many short-lived shells in a row: every one is in the log with its command, nothing needs /proc.
	const count = 300
	for i := 0; i < count; i++ {
		fpm.Request(1, "shell", "uname -s")
	}
	fpm.waitLines("done op=shell", count, killScale(2*time.Minute))
	evs = a.waitEvents(killScale(60*time.Second), "all short-lived shells", func(evs []Ev) bool {
		return len(shellExecs(evs, sh, "uname -s")) >= count
	})
	for _, e := range shellExecs(evs, sh, "uname -s") {
		if e.RootPID() != fpm.PID || !e.complete() || e.missingFields() > 0 {
			t.Fatalf("short-lived shell without full evidence: %s", e.Line)
		}
	}
	if lost := ofType(a.Events(), "agent.gap"); len(lost) != 0 {
		t.Errorf("%d agent.gap events", len(lost))
	}
}

func TestPHPWorkerReplacementKeepsTheTree(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	d := newProgDir(t)
	fpm := d.startFleet(n.FPM, 2, 3) // every worker ends after three requests, like pm.max_requests = 3
	a := startAgent(t, agentCfg{Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true})
	first := fpm.WorkerPIDs()

	// Two rounds: every worker serves three requests and ends, the master replaces it before the next round.
	for round := 1; round <= 2; round++ {
		for w := 0; w < 2; w++ {
			for i := 0; i < 3; i++ {
				fpm.Request(w, "ping")
			}
		}
		fpm.waitLines("worker started", 2+2*round, killScale(20*time.Second))
		time.Sleep(100 * time.Millisecond)
	}
	all := fpm.WorkerPIDs()
	evs := a.waitEvents(killScale(20*time.Second), "the replacement workers", func(evs []Ev) bool {
		for _, pid := range all[len(first):] {
			if len(kinds(ofPID(evs, pid))) == 0 {
				return false
			}
		}
		return true
	})
	ids := map[string]bool{}
	for _, pid := range all[len(first):] {
		for _, e := range ofPID(evs, pid) {
			if e.Role() != "descendant" || e.Depth() != 1 || e.RootPID() != fpm.PID {
				t.Errorf("replacement worker %d: role %s depth %d root %d", pid, e.Role(), e.Depth(), e.RootPID())
			}
			if e.Type() == "process.fork" {
				ids[e.ID()] = true
			}
		}
	}
	if len(ids) != len(all)-len(first) {
		t.Errorf("%d distinct identities for %d replacement workers", len(ids), len(all)-len(first))
	}
	for _, pid := range first {
		if k := kinds(ofPID(evs, pid)); !strings.HasSuffix(k, "exit") {
			t.Errorf("replaced worker %d: [%s]", pid, k)
		}
	}
	if len(ofType(evs, "agent.gap")) != 0 {
		t.Error("worker replacement must not look like a gap")
	}
}

// A graceful reload of PHP-FPM: the master executes itself again (same PID), forks a new master and ends. The new
// master and its workers stay in the tree as descendants of the original root.
func TestPHPReloadReexecutesTheMasterAndForksANewOne(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	d := newProgDir(t)
	fpm := d.startFleet(n.FPM, 2, 0)
	a := startAgent(t, agentCfg{Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true})

	fpm.send(phpCmd{Worker: -1, Op: "reload"})
	newMaster := intAfter(fpm.waitLines("new master started", 1, killScale(20*time.Second))[0], "pid")
	fpm.waitLines("master up", 3, killScale(20*time.Second)) // the first start, the re-executed master, the new master
	evs := a.waitEvents(killScale(30*time.Second), "the new master and its workers", func(evs []Ev) bool {
		workers := filterEv(evs, func(e Ev) bool {
			return e.Type() == "process.fork" && e.parentPID() == newMaster && e.Depth() == 2
		})
		return len(workers) >= 2 && len(ofPID(evs, fpm.PID)) > 0 && strings.Contains(kinds(ofPID(evs, fpm.PID)), "exit")
	})
	re := execsWith(evs, func(e Ev) bool { return e.PID() == fpm.PID })
	if len(re) != 1 || re[0].Role() != "root" || re[0].execIndex() != 1 || !argvIs(re[0], filepath.Join(d.dir, n.FPM), "2", "20") {
		t.Errorf("the reload must show the master's exec as the root: %d events", len(re))
	}
	nm := ofPID(evs, newMaster)
	if len(nm) == 0 || nm[0].Role() != "descendant" || nm[0].Depth() != 1 || nm[0].RootPID() != fpm.PID || nm[0].parentPID() != fpm.PID {
		t.Fatalf("the new master must be a depth 1 descendant of the old root: %v", kinds(nm))
	}
	for _, e := range filterEv(evs, func(e Ev) bool { return e.Type() == "process.fork" && e.parentPID() == newMaster }) {
		if e.RootPID() != fpm.PID || e.Depth() != 2 {
			t.Errorf("worker of the new master: root %d depth %d", e.RootPID(), e.Depth())
		}
	}
	// The old root is gone, the tree is not.
	if got := kinds(ofPID(evs, fpm.PID)); !strings.HasSuffix(got, "exit") {
		t.Errorf("old master [%s]", got)
	}
}

// --- 5. the visibility boundary: PHP code that never starts a process --------------------------

func TestPHPInProcessNetworkConnectionIsNotAProcessEvent(t *testing.T) {
	requireRoot(t)
	outEnsureLoopback(t)
	n := phpNames()
	sh := phpShellImage(t)
	d := newProgDir(t)
	fpm := d.startFleet(n.FPM, 1, 0)
	a := startAgent(t, agentCfg{Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		k, _ := c.Read(buf)
		got <- string(buf[:k])
	}()

	before := processEventCount(a.Events())
	fpm.Request(0, "sock", ln.Addr().String(), "pw-sock-hello")
	fpm.waitLines("done op=sock", 1, killScale(10*time.Second))
	select {
	case msg := <-got:
		if msg != "pw-sock-hello" {
			t.Fatalf("the listener received %q", msg)
		}
	case <-time.After(killScale(5 * time.Second)):
		t.Fatal("the worker's outbound connection never arrived")
	}
	time.Sleep(killScale(500 * time.Millisecond)) // the log must have had every chance to show something
	evs := a.Events()
	if after := processEventCount(evs); after != before {
		t.Fatalf("an outbound connection by the worker itself produced %d process events; the process telemetry is blind to it by design", after-before)
	}
	// The control: the same worker starting a shell is visible at once.
	fpm.Request(0, "shell", "echo control")
	a.waitEvents(killScale(10*time.Second), "the control shell", func(evs []Ev) bool { return len(shellExecs(evs, sh, "echo control")) == 1 })
}

// A worker that forks and keeps running the same program, without an exec, is a fork with the inherited image:
// there is no exec event, and a response rule at fork time sees nothing but the inherited image.
func TestPHPForkWithoutExecIsAForkWithTheInheritedImage(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	d := newProgDir(t)
	name := n.Tok.Prefix() + "-php-fpm-solo"
	a := startAgent(t, agentCfg{Watch: []string{name}, CaptureArgv: true})
	p := d.start(name, "fork-noexec")
	childLine := p.waitLine("child ", killScale(10*time.Second))
	child := intAfter(childLine, "pid")
	evs := a.waitEvents(killScale(20*time.Second), "the child's exit", func(evs []Ev) bool {
		return strings.Contains(kinds(ofPID(evs, child)), "exit")
	})
	if got := kinds(ofPID(evs, child)); got != "fork,exit" {
		t.Fatalf("the child of a fork without exec has [%s], want fork,exit", got)
	}
	f := ofPID(evs, child)[0]
	if f.Image() != name || f.str("process.image_state") != "inherited" || f.Role() != "descendant" || f.RootPID() != p.PID {
		t.Errorf("image %q state %s role %s root %d", f.Image(), f.str("process.image_state"), f.Role(), f.RootPID())
	}
}

// --- 6. response rules ---------------------------------------------------------------------

func killResults(evs []Ev) []Ev { return ofType(evs, "response.kill_result") }

func outcomeOf(e Ev) string { return e.str("details.outcome") }

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// exitOf returns the process.exit event of pid, if the log has one.
func exitOf(evs []Ev, pid int) *Ev {
	for _, e := range ofPID(evs, pid) {
		if e.Type() == "process.exit" {
			e := e
			return &e
		}
	}
	return nil
}

// lineOf is the log line of an event for a failure message; the event may be missing.
func lineOf(e *Ev) string {
	if e == nil {
		return "(no event)"
	}
	return e.Line
}

// A rule for "php" while the watch pattern is php-fpm: the workers fork with the master's image, so they match the
// rule too. This is the failure mode of a broad kill rule; the test documents it on a disposable fleet.
func TestPHPBroadKillRuleKillsTheWorkersItWasMeantToProtect(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	d := newProgDir(t)
	fpm := d.startFleet(n.FPM, 2, 0)
	existing := fpm.WorkerPIDs()
	a := startAgent(t, agentCfg{
		Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true,
		KillEnabled: true, KillFields: []string{"image"}, KillStrings: []string{"php"},
	})
	// The agent says so at start: a rule that matches the watched program is probably a mistake.
	started := ofType(a.Events(), "agent.started")[0]
	if w, _ := started.get("details.kill.warnings").([]any); len(w) != 1 || !strings.Contains(w[0].(string), "kill.strings[0]") {
		t.Errorf("agent.started warnings: %v", started.get("details.kill.warnings"))
	}

	evs := a.waitEvents(killScale(30*time.Second), "kills of PHP-FPM workers", func(evs []Ev) bool {
		n := 0
		for _, e := range killResults(evs) {
			if outcomeOf(e) == "signal_sent" && e.Image() == n0(fpm) {
				n++
			}
		}
		return n >= 4
	})
	a.Stop() // end the storm before anything else
	evs = a.Events()

	for _, e := range killResults(evs) {
		if e.PID() == fpm.PID {
			t.Fatalf("the root must never be a target: %s", e.Line)
		}
		if e.Role() != "descendant" {
			t.Errorf("kill target with role %s", e.Role())
		}
	}
	killedExisting := 0
	for _, pid := range existing {
		if x := exitOf(evs, pid); x != nil && x.num("details.signal") == 9 {
			killedExisting++
		}
	}
	if killedExisting != len(existing) {
		t.Errorf("%d of the %d workers that existed at the start were killed", killedExisting, len(existing))
	}
	if !alive(fpm.PID) {
		t.Error("the master survived (it is the root), but the service has lost every worker it forked")
	}
	if len(fpm.Lines("worker started")) <= len(existing) {
		t.Error("the master was expected to keep forking replacements")
	}
	_ = evs
}

// n0 is the image name of the fleet's master and workers.
func n0(f *phpFleet) string { return f.Name }

// The guard keeps the workers alive; what a worker starts is still judged by the rules.
func TestPHPSpareRootImageKeepsWorkersAliveAndStillKillsHelpers(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	d := newProgDir(t, n.Evil)
	fpm := d.startFleet(n.FPM, 2, 0)
	existing := fpm.WorkerPIDs()
	a := startAgent(t, agentCfg{
		Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true,
		KillEnabled: true, KillFields: []string{"image"}, KillStrings: []string{"php"}, KillRegex: []string{"^" + n.Evil + "$"},
		KillSpareRootImage: true,
	})
	started := ofType(a.Events(), "agent.started")[0]
	if started.get("details.kill.spare_root_image") != true {
		t.Errorf("agent.started: spare_root_image %v", started.get("details.kill.spare_root_image"))
	}
	if w, _ := started.get("details.kill.warnings").([]any); len(w) != 0 {
		t.Errorf("with the guard on there is nothing to warn about: %v", w)
	}

	// The two workers that exist at the start hit the rule "php" and are spared, and the audit says so.
	evs := a.waitEvents(killScale(20*time.Second), "the spared workers", func(evs []Ev) bool {
		c := 0
		for _, e := range killResults(evs) {
			if outcomeOf(e) == "skipped" && e.str("details.reason") == "root_image_spared" {
				c++
			}
		}
		return c >= len(existing)
	})
	for _, e := range killResults(evs) {
		if outcomeOf(e) != "skipped" {
			t.Fatalf("nothing may be killed yet: %s", e.Line)
		}
	}
	// A helper that a worker starts matches the second rule and is killed.
	fpm.Launch(0, n.Evil, "sleep", "60000")
	line := fpm.waitLines("started op=launch", 1, killScale(10*time.Second))[0]
	evil := intAfter(line, "pid")
	evs = a.waitEvents(killScale(20*time.Second), "the helper to be killed", func(evs []Ev) bool { return exitOf(evs, evil) != nil })
	x := exitOf(evs, evil)
	if x.num("details.signal") != 9 {
		t.Errorf("the helper ended with %v, want SIGKILL", x.get("details"))
	}
	var sent bool
	for _, e := range killResults(evs) {
		if e.PID() == evil && outcomeOf(e) == "signal_sent" {
			sent = true
			if e.get("details.rules") == nil || x.str("details.response_action_id") != e.str("details.action_id") {
				t.Errorf("the exit must carry the action id: %v vs %v", x.str("details.response_action_id"), e.str("details.action_id"))
			}
		}
	}
	if !sent {
		t.Error("no kill_result with signal_sent for the helper")
	}
	// Every worker is still there, nothing was replaced.
	for _, pid := range existing {
		if !alive(pid) || exitOf(evs, pid) != nil {
			t.Errorf("worker %d was lost", pid)
		}
	}
	if got := len(fpm.Lines("worker started")); got != len(existing) {
		t.Errorf("the master forked %d workers, want no replacement beyond the %d", got, len(existing))
	}
}

// Narrow rules, no guard needed: shells and interpreters are targets, the service's own image is not even matched.
func TestPHPNarrowRulesKillShellsAndInterpretersButNotWorkers(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	sh := phpShellImage(t)
	d := newProgDir(t, n.CLI)
	fpm := d.startFleet(n.FPM, 2, 0)
	existing := fpm.WorkerPIDs()
	// php8.4 (the CLI) but not php-fpm8.4; the shell by its executable name, which is dash on Debian.
	a := startAgent(t, agentCfg{
		Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true,
		KillEnabled: true, KillFields: []string{"image"}, KillRegex: []string{"^(" + sh + "|bash)$", `-php8\.4$`},
	})
	if w, _ := ofType(a.Events(), "agent.started")[0].get("details.kill.warnings").([]any); len(w) != 0 {
		t.Errorf("a narrow rule must not warn: %v", w)
	}

	fpm.Request(0, "shell-bg", "sleep 30")
	fpm.Launch(1, n.CLI, "sleep", "60000")
	fpm.Request(1, "direct", "/bin/true", "ordinary")
	lines := fpm.waitLines("started op=", 2, killScale(10*time.Second))
	var targets []int
	for _, l := range lines {
		targets = append(targets, intAfter(l, "pid"))
	}
	// The log has no order between the exits of different processes: wait for all three, the ordinary program included.
	evs := a.waitEvents(killScale(30*time.Second), "both targets and /bin/true to end", func(evs []Ev) bool {
		if exitOf(evs, targets[0]) == nil || exitOf(evs, targets[1]) == nil {
			return false
		}
		ordinary := execOfImage(evs, "true")
		return len(ordinary) == 1 && exitOf(evs, ordinary[0].PID()) != nil
	})
	for _, pid := range targets {
		if x := exitOf(evs, pid); x == nil || x.num("details.signal") != 9 {
			t.Errorf("target %d was not ended by SIGKILL: %s", pid, lineOf(x))
		}
	}
	// The ordinary program and the workers were not touched.
	if ordinary := execOfImage(evs, "true"); len(ordinary) != 1 {
		t.Errorf("want one exec of /bin/true, got %d", len(ordinary))
	} else if x := exitOf(evs, ordinary[0].PID()); x == nil || x.num("details.signal") != -1 {
		t.Errorf("/bin/true must run to its end: %s", lineOf(x))
	}
	for _, e := range killResults(evs) {
		if e.Image() == n.FPM {
			t.Errorf("a worker was a target: %s", e.Line)
		}
	}
	for _, pid := range existing {
		if !alive(pid) {
			t.Errorf("worker %d was lost", pid)
		}
	}
}

func TestPHPDryRunReportsWithoutKilling(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	sh := phpShellImage(t)
	d := newProgDir(t)
	fpm := d.startFleet(n.FPM, 1, 0)
	a := startAgent(t, agentCfg{
		Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true,
		KillEnabled: true, KillDryRun: true, KillFields: []string{"image"}, KillRegex: []string{"^(" + sh + "|bash)$"},
	})
	fpm.Request(0, "shell-bg", "sleep 1")
	pid := intAfter(fpm.waitLines("started op=shell-bg", 1, killScale(10*time.Second))[0], "pid")
	evs := a.waitEvents(killScale(30*time.Second), "the shell to end by itself", func(evs []Ev) bool { return exitOf(evs, pid) != nil })
	x := exitOf(evs, pid)
	if x.num("details.signal") != -1 || x.num("details.exit_code") != 0 {
		t.Errorf("a dry run must not kill: %v", x.get("details"))
	}
	var dry bool
	for _, e := range killResults(evs) {
		if e.PID() == pid {
			dry = true
			if outcomeOf(e) != "dry_run" || e.get("details.dry_run") != true {
				t.Errorf("outcome %s", outcomeOf(e))
			}
		}
	}
	if !dry {
		t.Error("the dry run must still audit the decision")
	}
}

// A watched process that is itself a root is never a target, whatever the rules say: in-process activity of a
// root cannot be stopped by these rules.
func TestPHPRootsAreNeverKilled(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	d := newProgDir(t)
	a := startAgent(t, agentCfg{
		Watch: []string{n.CLI}, CaptureArgv: true,
		KillEnabled: true, KillFields: []string{"image"}, KillStrings: []string{"php"},
	})
	cli := d.start(n.CLI, "sleep", "60000") // a PHP CLI worker started by cron or a supervisor: a root of its own
	a.waitEvents(killScale(10*time.Second), "the root", func(evs []Ev) bool { return len(ofPID(evs, cli.PID)) > 0 })
	time.Sleep(killScale(700 * time.Millisecond))
	if !alive(cli.PID) {
		t.Fatal("a watched root was killed")
	}
	if n := len(killResults(a.Events())); n != 0 {
		t.Errorf("%d kill results for a root", n)
	}
}

// How long the reaction takes against a real long-running helper, and what happens to programs that are faster.
func TestPHPKillReactionAgainstSlowAndFastPrograms(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	sh := phpShellImage(t)
	d := newProgDir(t, n.Evil)
	fpm := d.startFleet(n.FPM, 1, 0)
	a := startAgent(t, agentCfg{
		Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true, Health: "10s",
		KillEnabled: true, KillFields: []string{"image"}, KillRegex: []string{"^" + n.Evil + "$", "^(" + sh + "|bash)$"},
	})

	const slow = 40
	for i := 0; i < slow; i++ {
		fpm.Launch(0, n.Evil, "sleep", "60000")
		fpm.waitLines("started op=launch", i+1, killScale(10*time.Second))
		time.Sleep(20 * time.Millisecond) // one target after the other, like requests arriving, not a burst
	}
	evs := a.waitEvents(killScale(60*time.Second), "all slow helpers to be killed", func(evs []Ev) bool {
		c := 0
		for _, e := range killResults(evs) {
			if e.Image() == n.Evil && outcomeOf(e) != "" {
				c++
			}
		}
		return c >= slow
	})
	var lat []int64
	for _, e := range killResults(evs) {
		if e.Image() != n.Evil {
			continue
		}
		if outcomeOf(e) != "signal_sent" {
			t.Errorf("a helper that runs for a minute must be reached: %s", outcomeOf(e))
			continue
		}
		var v int64
		for _, c := range e.str("details.attempt_latency_ns") {
			v = v*10 + int64(c-'0')
		}
		lat = append(lat, v)
		if x := exitOf(evs, e.PID()); x == nil || x.num("details.signal") != 9 {
			// the exit record can still be on its way; wait once
			evs = a.waitEvents(killScale(10*time.Second), "the exit of a killed helper", func(evs []Ev) bool { return exitOf(evs, e.PID()) != nil })
			if x = exitOf(evs, e.PID()); x.num("details.signal") != 9 {
				t.Errorf("helper %d: signal_sent but it ended with %v", e.PID(), x.get("details"))
			}
		}
	}
	mean, max, p95 := latencyStats(lat)
	t.Logf("signal attempt after the kernel's exec record, %d long-running helpers: mean %.3f ms, p95 %.3f ms, max %.3f ms", len(lat), mean, p95, max)
	if max > 1000 {
		t.Errorf("a signal attempt took %.1f ms", max)
	}

	// Short-lived shells: the outcome depends on who is faster, and it is reported either way.
	const fast = 100
	for i := 0; i < fast; i++ {
		fpm.Request(0, "shell", "uname -s")
	}
	fpm.waitLines("done op=shell", fast, killScale(2*time.Minute))
	time.Sleep(time.Second) // every decision is made within milliseconds; let the last results arrive
	evs = a.waitEvents(killScale(30*time.Second), "all short-lived shells to be decided", func(evs []Ev) bool {
		c := 0
		for _, e := range killResults(evs) {
			if e.Image() == sh && outcomeOf(e) != "" {
				c++
			}
		}
		return c >= fast
	})
	outcomes := map[string]int{}
	killedBySignal, endedBySelf := 0, 0
	for _, e := range killResults(evs) {
		if e.Image() != sh {
			continue
		}
		o := outcomeOf(e)
		if o == "skipped" {
			o += ":" + e.str("details.reason")
		}
		outcomes[o]++
		if o == "signal_sent" {
			// A signal the kernel accepted is not a death: the shell may have ended by itself just before.
			if x := exitOf(evs, e.PID()); x != nil && x.num("details.signal") == 9 {
				killedBySignal++
			} else {
				endedBySelf++
			}
		}
	}
	t.Logf("%d short-lived shells (sh -c 'uname -s'): outcomes %v; of the signals accepted, %d ended with SIGKILL and %d had ended by themselves",
		fast, outcomes, killedBySignal, endedBySelf)
	for o := range outcomes {
		switch o {
		case "signal_sent", "already_exited", "skipped:match_no_longer_verified", "skipped:identity_unverified":
		default:
			t.Errorf("unexpected outcome %q for a short-lived shell", o)
		}
	}
}

func latencyStats(ns []int64) (meanMS, maxMS, p95MS float64) {
	if len(ns) == 0 {
		return
	}
	sorted := append([]int64(nil), ns...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	var sum int64
	for _, v := range sorted {
		sum += v
	}
	return float64(sum) / float64(len(sorted)) / 1e6, float64(sorted[len(sorted)-1]) / 1e6, float64(sorted[len(sorted)*95/100]) / 1e6
}

// --- 7. large arguments on every output ------------------------------------------------------

func TestPHPLargeArgumentsSurviveEveryTransport(t *testing.T) {
	requireRoot(t)
	tcp := outNewTCPServer(t, outTCPOpts{})
	udp := outNewUDPServer(t)
	hook := outNewHookServer(t)
	n := phpNames()
	sh := phpShellImage(t)
	d := newProgDir(t)
	fpm := d.startFleet(n.FPM, 1, 0)
	a := outStart(t, outCfg{
		Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true, ArgvMaxBytes: 16383,
		TCP: tcp.Addr, UDP: udp.Addr, Webhook: hook.URL + "/events", Health: "500ms",
	})

	small := "echo " + strings.Repeat("S", 500)  // fits a datagram
	big := "echo " + strings.Repeat("N", 12000)  // complete, too large for the default 8192 byte datagram
	huge := "echo " + strings.Repeat("O", 30000) // cut at the limit: partial argument, too large for UDP as well
	for _, c := range []string{small, big, huge} {
		fpm.Request(0, "shell", c)
	}
	fpm.waitLines("done op=shell", 3, killScale(30*time.Second))
	a.waitEvents(killScale(20*time.Second), "the three shells", func(evs []Ev) bool {
		c := 0
		for _, e := range ofType(evs, "process.exit") {
			if e.Image() == sh {
				c++
			}
		}
		return c >= 3
	})
	evs := outStopAndEvents(t, a)
	byID := outByID(evs)
	want := outRemoteEvents(evs)

	// The log lines are valid JSON and carry the arguments as written.
	var bigEv, hugeEv, smallEv *Ev
	for _, e := range execsWith(evs, func(e Ev) bool { return e.Image() == sh }) {
		e := e
		switch a := e.argv(); {
		case len(a) == 4 && a[3] == big:
			bigEv = &e
		case len(a) == 4 && a[3] == small:
			smallEv = &e
		case len(a) == 3 && !e.complete():
			hugeEv = &e
		}
	}
	if bigEv == nil || smallEv == nil || hugeEv == nil {
		t.Fatalf("exec events: small %v big %v huge %v", smallEv != nil, bigEv != nil, hugeEv != nil)
	}
	if !bigEv.complete() || len(bigEv.Line) < 12000 || len(hugeEv.str("process.argv_capture.partial.value")) != 16383-9 {
		t.Errorf("big: complete=%v line %d bytes; huge partial %d bytes", bigEv.complete(), len(bigEv.Line), len(hugeEv.str("process.argv_capture.partial.value")))
	}

	// TCP and webhook deliver every event, byte for byte, however large it is.
	outWait(t, killScale(30*time.Second), "the TCP connection to be closed", func() bool { return tcp.NumConns() > 0 && tcp.AllEnded() })
	tcpCount := outAssertIdentical(t, "tcp", tcp.LineBytes(), byID)
	if miss := outMissing(want, tcpCount); len(miss) > 0 {
		t.Errorf("tcp is missing %d events, e.g. %v", len(miss), miss[:min(3, len(miss))])
	}
	var bodies [][]byte
	for _, r := range hook.Accepted() {
		bodies = append(bodies, r.Body)
	}
	hookCount := outAssertIdentical(t, "webhook", bodies, byID)
	if miss := outMissing(want, hookCount); len(miss) > 0 {
		t.Errorf("webhook is missing %d events, e.g. %v", len(miss), miss[:min(3, len(miss))])
	}
	sawBig := false
	for _, l := range tcp.LineBytes() {
		if len(l) > 12000 {
			sawBig = true
		}
	}
	if !sawBig {
		t.Error("no line above 12000 bytes arrived over TCP")
	}

	// UDP: an event above the datagram limit is not sent, and that is counted; nothing is cut.
	stopped := evs[len(evs)-1]
	dropped := outOutput(stopped, "udp", "dropped_too_large")
	if dropped == 0 {
		t.Error("udp: events above max_bytes must be counted as dropped_too_large")
	}
	handed := outOutput(stopped, "udp", "handed_over")
	outWaitDatagrams(udp, handed, 20*time.Second)
	for _, dg := range udp.Datagrams() {
		if len(dg) > 8192 {
			t.Errorf("udp: a datagram of %d bytes exceeds the limit", len(dg))
		}
		if id := outEventID(dg); byID[id].Line+"\n" != string(dg) && byID[id].Line != string(dg) {
			t.Errorf("udp: the datagram of event %s differs from its log line", id)
		}
	}
	t.Logf("udp: %d datagrams, %d events dropped as too large; tcp %d lines, webhook %d bodies; the largest line is %d bytes",
		len(udp.Datagrams()), dropped, len(tcp.LineBytes()), len(bodies), maxLen(tcp.LineBytes()))
}

func maxLen(ls [][]byte) int {
	m := 0
	for _, l := range ls {
		m = max(m, len(l))
	}
	return m
}

// A kill decision names its ancestors with their arguments, so it can be read on its own: the worker that ran
// PHP and the shell that was told what to do are in the audit event, even if their own events are elsewhere.
func TestPHPKillAuditExplainsItselfThroughTheChain(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	sh := phpShellImage(t)
	d := newProgDir(t)
	fpm := d.startFleet(n.FPM, 1, 0)
	worker := fpm.WorkerPIDs()[0]
	a := startAgent(t, agentCfg{
		Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true,
		KillEnabled: true, KillFields: []string{"image"}, KillRegex: []string{"^sleep$"}, KillSpareRootImage: true,
	})
	fpm.Request(0, "shell-bg", "sleep 30")
	shell := intAfter(fpm.waitLines("started op=shell-bg", 1, killScale(10*time.Second))[0], "pid")
	evs := a.waitEvents(killScale(20*time.Second), "the kill of sleep", func(evs []Ev) bool {
		for _, e := range killResults(evs) {
			if e.Image() == "sleep" && outcomeOf(e) != "" {
				return true
			}
		}
		return false
	})
	var res Ev
	for _, e := range killResults(evs) {
		if e.Image() == "sleep" {
			res = e
		}
	}
	chain, _ := res.get("details.chain").([]any)
	if len(chain) != 3 || res.get("details.chain_truncated") != false {
		t.Fatalf("chain %v", res.get("details.chain"))
	}
	link := func(i int) Ev { return Ev{Raw: chain[i].(map[string]any)} }
	if link(0).num("pid") != fpm.PID || link(0).str("image") != n.FPM {
		t.Errorf("link 0 (the master): %v", chain[0])
	}
	if link(1).num("pid") != worker || link(1).str("image") != n.FPM {
		t.Errorf("link 1 (the worker): %v", chain[1])
	}
	l2 := link(2)
	var args []string
	for _, v := range l2.Raw["argv"].([]any) {
		args = append(args, v.(string))
	}
	if l2.num("pid") != shell || l2.str("image") != sh || strings.Join(args, "|") != "sh|-c|--|sleep 30" || l2.Raw["argv_complete"] != true {
		t.Errorf("link 2 (the shell that was told what to do): %v", chain[2])
	}
	// The audit event and the earlier process events agree on the identity of every link.
	if link(0).str("process_id") != res.str("root.process_id") || link(2).str("process_id") != res.str("parent.process_id") {
		t.Errorf("chain identities do not match root %s / parent %s", res.str("root.process_id"), res.str("parent.process_id"))
	}
}

// A worker that replaces itself with another program (same PID, no fork) is judged by the rules as that program. It is
// a descendant, not a root, so the rule can end it: this is the response opportunity for exec-in-place.
func TestPHPWorkerThatReplacesItselfWithAKillableProgramIsKilled(t *testing.T) {
	requireRoot(t)
	n := phpNames()
	d := newProgDir(t, n.Evil)
	fpm := d.startFleet(n.FPM, 2, 0)
	workers := fpm.WorkerPIDs()
	a := startAgent(t, agentCfg{
		Watch: []string{n.Tok.Prefix() + "-php-fpm"}, CaptureArgv: true,
		KillEnabled: true, KillFields: []string{"image"}, KillRegex: []string{"^" + n.Evil + "$"}, KillSpareRootImage: true,
	})
	fpm.send(phpCmd{Worker: 0, Op: "exec", Mode: "sleep", Args: []string{filepath.Join(d.dir, n.Evil), "60000"}})
	evs := a.waitEvents(killScale(20*time.Second), "the replaced worker to be killed", func(evs []Ev) bool { return exitOf(evs, workers[0]) != nil })
	x := exitOf(evs, workers[0])
	if x.num("details.signal") != 9 {
		t.Fatalf("the worker that became %s ended with %v", n.Evil, x.get("details"))
	}
	var res *Ev
	for _, e := range killResults(evs) {
		if e.PID() == workers[0] {
			e := e
			res = &e
		}
	}
	if res == nil || outcomeOf(*res) != "signal_sent" || res.Role() != "descendant" || res.str("details.trigger_event_type") != "process.exec" || res.num("details.exec_index") != 1 {
		t.Fatalf("the audit of the exec in place: %v", res)
	}
	if prev := execOfImage(evs, n.Evil); len(prev) != 1 || prev[0].str("details.previous_image") != n.FPM {
		t.Errorf("the exec event must name the image that was replaced")
	}
	// The other worker and the master are untouched, and the master replaces the lost worker.
	if !alive(workers[1]) || !alive(fpm.PID) {
		t.Error("only the replaced worker may be lost")
	}
	fpm.waitLines("worker started", len(workers)+1, killScale(10*time.Second))
}
