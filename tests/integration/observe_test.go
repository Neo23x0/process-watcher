//go:build linux

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// startNode starts the root of a recipe tree (its name is the program name).
func (d *progDir) startNode(r recipe) *prog {
	d.t.Helper()
	for _, n := range recipeNames(r) {
		d.add(n)
	}
	return d.startEnv(r.Name, "node", []string{"PW_E2E_RECIPE=" + r.json()})
}

func recipeNames(r recipe) []string {
	names := []string{r.Name}
	for _, c := range r.Children {
		names = append(names, recipeNames(c)...)
	}
	return names
}

// pidsByName collects "up pid=N name=X" lines until the process ended or n
// distinct processes announced themselves.
func upPIDs(t *testing.T, p *prog, want int, timeout time.Duration) map[string]int {
	t.Helper()
	got := map[string]int{}
	deadline := time.After(timeout)
	for len(got) < want {
		select {
		case l, ok := <-p.lines:
			if !ok {
				t.Fatalf("tree ended early, announced %v", got)
			}
			if strings.HasPrefix(l, "up ") {
				got[strAfter(l, "name")] = intAfter(l, "pid")
			}
		case <-deadline:
			t.Fatalf("only %v announced themselves", got)
		}
	}
	return got
}

func TestRootRunningBeforeStartIsDiscoveredOnce(t *testing.T) {
	requireRoot(t)
	d := newProgDir(t)
	root := d.startNode(recipe{Name: "pwtest-nginx", Action: "sleep:30000", Children: []recipe{
		{Name: "pwtest-worker", Action: "sleep:30000", Children: []recipe{{Name: "pwtest-leaf", Mode: "sleep"}}},
		{Name: "pwtest-cache", Mode: "sleep"},
	}})
	pids := upPIDs(t, root, 4, 10*time.Second)

	a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}, CaptureArgv: true})
	evs := a.Events()

	disc := ofType(evs, "process.discovered")
	if len(disc) != 4 {
		t.Fatalf("want root plus three living descendants discovered, got %d:\n%s", len(disc), summarize(evs, 40))
	}
	byPID := map[int]Ev{}
	for _, e := range disc {
		byPID[e.PID()] = e
	}
	rootEv := byPID[pids["pwtest-nginx"]]
	if rootEv.Role() != "root" || rootEv.Depth() != 0 || rootEv.str("process.image_state") != "snapshot" || rootEv.str("source") != "snapshot" {
		t.Errorf("root %+v", rootEv.Raw["lineage"])
	}
	want := map[string]int{"pwtest-worker": 1, "pwtest-cache": 1, "pwtest-leaf": 2}
	for name, depth := range want {
		e := byPID[pids[name]]
		if e.Role() != "descendant" || e.Depth() != depth || e.RootPID() != pids["pwtest-nginx"] || e.str("parent.relationship_source") != "snapshot_ppid" {
			t.Errorf("%s: role %s depth %d root %d parent source %s", name, e.Role(), e.Depth(), e.RootPID(), e.str("parent.relationship_source"))
		}
		if e.Image() != name {
			t.Errorf("image %q, want %q", e.Image(), name)
		}
	}
	// Discovery precedes agent.ready; nothing is reported twice, also not by later reconciliations.
	ready := ofType(evs, "agent.ready")[0].Seq()
	for _, e := range disc {
		if e.Seq() > ready {
			t.Errorf("process.discovered #%d after agent.ready #%d", e.Seq(), ready)
		}
	}
	if args := rootEv.argv(); len(args) == 0 || args[0] != filepath.Join(d.dir, "pwtest-nginx") {
		t.Errorf("snapshot arguments (read from /proc with an identity check): %v", args)
	}
	time.Sleep(5 * time.Second) // several reconcile intervals
	if n := len(ofType(a.Events(), "process.discovered")); n != 4 {
		t.Errorf("a reconciliation repeated the discovery: %d", n)
	}
}

func TestRootStartingLaterAndTheChainShareOneRoot(t *testing.T) {
	d := newProgDir(t)
	a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}})
	// nginx -> helper -> sh -> curl, each generation is another program name.
	root := d.startNode(recipe{Name: "pwtest-nginx", Children: []recipe{
		{Name: "pwtest-helper", Children: []recipe{
			{Name: "pwtest-sh", Children: []recipe{{Name: "pwtest-curl", Mode: "sleep", Args: []string{"800"}}}},
		}},
	}})
	root.wait(20 * time.Second)

	evs := a.waitEvents(10*time.Second, "the chain's exits", func(evs []Ev) bool {
		return len(filterEv(ofType(evs, "process.exit"), func(e Ev) bool { return e.Image() == "pwtest-curl" })) > 0
	})
	rootExec := filterEv(ofType(evs, "process.exec"), func(e Ev) bool { return e.PID() == root.PID })
	if len(rootExec) != 1 || rootExec[0].Role() != "root" || rootExec[0].Depth() != 0 || rootExec[0].str("lineage.complete") != "" && rootExec[0].get("lineage.complete") != true {
		t.Fatalf("the exec of the matching program creates the root:\n%s", summarize(evs, 30))
	}
	depth := map[string]int{"pwtest-helper": 1, "pwtest-sh": 2, "pwtest-curl": 3}
	for name, want := range depth {
		execs := filterEv(ofType(evs, "process.exec"), func(e Ev) bool { return e.Image() == name })
		if len(execs) != 1 {
			t.Fatalf("%s: %d exec events", name, len(execs))
		}
		e := execs[0]
		if e.Depth() != want || e.RootPID() != root.PID || e.Role() != "descendant" {
			t.Errorf("%s depth %d root %d role %s", name, e.Depth(), e.RootPID(), e.Role())
		}
		anc, _ := e.get("lineage.ancestors").([]any)
		if len(anc) != want || !strings.Contains(anc[0].(string), ":"+strconv.Itoa(root.PID)+":") {
			t.Errorf("%s ancestors %v", name, anc)
		}
		// The fork before the exec inherits the image of its creator.
		forks := filterEv(ofPID(evs, e.PID()), func(e Ev) bool { return e.Type() == "process.fork" })
		if len(forks) != 1 || forks[0].str("process.image_state") != "inherited" {
			t.Errorf("%s fork: %d", name, len(forks))
		}
	}
	// Direct parent of curl is sh, whose process_id is the last ancestor.
	curl := filterEv(ofType(evs, "process.exec"), func(e Ev) bool { return e.Image() == "pwtest-curl" })[0]
	if curl.str("parent.image") != "pwtest-sh" || curl.str("parent.relationship_source") != "fork" {
		t.Errorf("parent %v", curl.Raw["parent"])
	}
	for _, e := range evs {
		if strings.HasPrefix(e.Type(), "process.") && (e.str("root.image") != "pwtest-nginx") {
			t.Errorf("root image %q in %s", e.str("root.image"), e.Type())
		}
	}
}

func TestShortLivedChildrenNeedNoProcAccess(t *testing.T) {
	d := newProgDir(t)
	a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}, CaptureArgv: true})
	n := 1000
	if v, err := strconv.Atoi(os.Getenv("PW_E2E_BURST")); err == nil && v > 0 {
		n = v
	}
	root := d.start("pwtest-nginx", "burst", strconv.Itoa(n))
	children := root.collect("child ", 5*time.Minute)
	if len(children) != n {
		t.Fatalf("helper reported %d children", len(children))
	}
	want := map[int]bool{}
	for _, l := range children {
		want[intAfter(l, "pid")] = true
	}
	evs := a.waitEvents(60*time.Second, "all exits", func(evs []Ev) bool {
		got := 0
		for _, e := range ofType(evs, "process.exit") {
			if want[e.PID()] {
				got++
			}
		}
		return got >= n
	})
	byPID := map[int][]Ev{}
	for _, e := range evs {
		if want[e.PID()] && strings.HasPrefix(e.Type(), "process.") {
			byPID[e.PID()] = append(byPID[e.PID()], e)
		}
	}
	for pid := range want {
		tl := byPID[pid]
		if kinds(tl) != "fork,exec,exit" {
			t.Fatalf("pid %d: records [%s]", pid, kinds(tl))
		}
		if tl[0].ID() != tl[1].ID() || tl[1].ID() != tl[2].ID() {
			t.Fatalf("pid %d: identity changed", pid)
		}
		if tl[1].Image() != "true" || tl[1].str("process.image_path") != "/usr/bin/true" || tl[1].Depth() != 1 || tl[1].RootPID() != root.PID {
			t.Fatalf("pid %d exec: image %q path %q depth %d", pid, tl[1].Image(), tl[1].str("process.image_path"), tl[1].Depth())
		}
	}
	code := a.Stop()
	if code != 0 {
		t.Fatalf("agent exit code %d", code)
	}
	stopped := ofType(a.Events(), "agent.stopped")
	if len(stopped) != 1 {
		t.Fatalf("agent.stopped: %d", len(stopped))
	}
	if lost := stopped[0].num("details.collector.lost_total"); lost != 0 {
		t.Errorf("no records may be lost under this load, lost %d", lost)
	}
	t.Logf("%d short lived children, all fork/exec/exit complete; kernel lost %d", n, stopped[0].num("details.collector.lost_total"))
}

func TestForkWithoutExecRepeatedExecAndFailedExec(t *testing.T) {
	t.Run("fork without exec", func(t *testing.T) {
		d := newProgDir(t)
		a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}})
		root := d.start("pwtest-nginx", "fork-noexec")
		line := root.waitLine("child ", 10*time.Second)
		child := intAfter(line, "pid")
		evs := a.waitEvents(10*time.Second, "child exit", func(evs []Ev) bool { return len(ofPID(evs, child)) >= 2 })
		tl := ofPID(evs, child)
		if kinds(tl) != "fork,exit" || tl[0].str("process.image_state") != "inherited" || tl[0].Image() != "pwtest-nginx" {
			t.Fatalf("child lifecycle [%s]", kinds(tl))
		}
		if code := tl[1].num("details.exit_code"); code != 7 || tl[1].get("details.signal") != nil {
			t.Errorf("exit code %d signal %v", code, tl[1].get("details.signal"))
		}
	})
	t.Run("repeated exec keeps the identity", func(t *testing.T) {
		d := newProgDir(t, "pwtest-a", "pwtest-b", "pwtest-c")
		a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}})
		root := d.startNode(recipe{Name: "pwtest-nginx", Children: []recipe{{Name: "pwtest-a", Mode: "exec-chain", Args: []string{"pwtest-b", "pwtest-c"}}}})
		root.wait(10 * time.Second)
		evs := a.waitEvents(10*time.Second, "chain exit", func(evs []Ev) bool {
			return len(filterEv(ofType(evs, "process.exit"), func(e Ev) bool { return e.Image() == "pwtest-c" })) > 0
		})
		last := filterEv(ofType(evs, "process.exit"), func(e Ev) bool { return e.Image() == "pwtest-c" })[0]
		tl := ofPID(evs, last.PID())
		if kinds(tl) != "fork,exec,exec,exec,exit" {
			t.Fatalf("[%s]", kinds(tl))
		}
		for i, e := range tl {
			if e.ID() != tl[0].ID() {
				t.Errorf("identity changed at %d", i)
			}
		}
		for i, want := range []int{1, 2, 3} {
			if got := tl[i+1].num("details.exec_index"); got != want {
				t.Errorf("exec %d has exec_index %d", i, got)
			}
		}
		if tl[2].str("details.previous_image") != "pwtest-a" || tl[3].str("details.previous_image") != "pwtest-b" {
			t.Errorf("previous images %v %v", tl[2].get("details.previous_image"), tl[3].get("details.previous_image"))
		}
	})
	t.Run("failed exec is not reported", func(t *testing.T) {
		d := newProgDir(t)
		a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}})
		root := d.start("pwtest-nginx", "exec-fail")
		root.waitLine("failed ", 10*time.Second)
		child := intAfter(root.waitLine("child ", 10*time.Second), "pid")
		evs := a.waitEvents(10*time.Second, "child exit", func(evs []Ev) bool { return len(ofPID(evs, child)) >= 3 })
		if got := kinds(ofPID(evs, root.PID)); got != "exec" && got != "exec,exit" {
			t.Errorf("the failed execve calls must not appear: root records [%s]", got)
		}
	})
}

func TestOrphanStaysInItsTree(t *testing.T) {
	d := newProgDir(t)
	a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}})
	// The root starts a child that lives on after the root ended, then starts its own child later.
	root := d.startNode(recipe{Name: "pwtest-nginx", Action: "leave", Children: []recipe{
		{Name: "pwtest-orphan", Action: "wait", DelayMS: 800, Children: []recipe{{Name: "pwtest-late", Mode: "sleep", Args: []string{"500"}}}},
	}})
	root.wait(10 * time.Second)
	evs := a.waitEvents(15*time.Second, "late child", func(evs []Ev) bool {
		return len(filterEv(ofType(evs, "process.exit"), func(e Ev) bool { return e.Image() == "pwtest-late" })) > 0
	})
	rootExit := filterEv(ofType(evs, "process.exit"), func(e Ev) bool { return e.PID() == root.PID })
	late := filterEv(ofType(evs, "process.exec"), func(e Ev) bool { return e.Image() == "pwtest-late" })
	if len(rootExit) != 1 || len(late) != 1 {
		t.Fatalf("root exit %d, late exec %d:\n%s", len(rootExit), len(late), summarize(evs, 30))
	}
	if rootExit[0].Seq() > late[0].Seq() {
		t.Fatal("the root must have ended before its grandchild started")
	}
	if late[0].RootPID() != root.PID || late[0].Depth() != 2 || late[0].str("parent.relationship_source") != "fork" {
		t.Errorf("late child: root %d depth %d", late[0].RootPID(), late[0].Depth())
	}
	// The orphan's real parent is init by now; the historical creator stays recorded.
	orphan := filterEv(ofType(evs, "process.exec"), func(e Ev) bool { return e.Image() == "pwtest-orphan" })[0]
	if orphan.str("parent.process_id") != rootExit[0].ID() {
		t.Errorf("orphan parent %s", orphan.str("parent.process_id"))
	}
}

func TestTwoIndependentRootsAndMatchingWorkers(t *testing.T) {
	d := newProgDir(t)
	a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}})
	r1 := d.startNode(recipe{Name: "pwtest-nginx", Children: []recipe{{Name: "pwtest-nginx-worker", Mode: "sleep", Args: []string{"600"}}}})
	r2 := d.startNode(recipe{Name: "pwtest-nginx-debug", Children: []recipe{{Name: "pwtest-x", Mode: "sleep", Args: []string{"600"}}}})
	r1.wait(10 * time.Second)
	r2.wait(10 * time.Second)
	evs := a.waitEvents(10*time.Second, "both trees", func(evs []Ev) bool { return len(ofType(evs, "process.exit")) >= 4 })
	roots := filterEv(evs, func(e Ev) bool {
		return strings.HasPrefix(e.Type(), "process.") && e.Role() == "root" && e.Type() == "process.exec"
	})
	if len(roots) != 2 {
		t.Fatalf("two independent roots expected, got %d", len(roots))
	}
	worker := filterEv(ofType(evs, "process.exec"), func(e Ev) bool { return e.Image() == "pwtest-nginx-worker" })[0]
	if worker.Role() != "descendant" || worker.RootPID() != r1.PID {
		t.Errorf("a matching worker below the master is a descendant of it: role %s root %d", worker.Role(), worker.RootPID())
	}
	x := filterEv(ofType(evs, "process.exec"), func(e Ev) bool { return e.Image() == "pwtest-x" })[0]
	if x.RootPID() != r2.PID {
		t.Errorf("trees are separate: root %d", x.RootPID())
	}
}

func TestDepthLimitSuppressesOnlyTheOutput(t *testing.T) {
	d := newProgDir(t)
	a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}, MaxDepth: 1})
	root := d.startNode(recipe{Name: "pwtest-nginx", Children: []recipe{
		{Name: "pwtest-d1", Children: []recipe{{Name: "pwtest-d2", Children: []recipe{{Name: "pwtest-d3", Mode: "sleep", Args: []string{"500"}}}}}},
	}})
	root.wait(10 * time.Second)
	evs := a.waitEvents(10*time.Second, "tree end", func(evs []Ev) bool { return len(ofType(evs, "process.exit")) >= 2 })
	time.Sleep(500 * time.Millisecond)
	evs = a.Events()
	for _, e := range evs {
		if strings.HasPrefix(e.Type(), "process.") && e.Depth() > 1 {
			t.Errorf("depth %d event %s despite watch.max_depth 1", e.Depth(), e.Type())
		}
	}
	if len(filterEv(ofType(evs, "process.exec"), func(e Ev) bool { return e.Image() == "pwtest-d1" })) != 1 {
		t.Error("depth 1 must still be reported")
	}
	// The deeper processes were tracked: their number is in the health data.
	a.Stop()
	st := ofType(a.Events(), "agent.stopped")[0]
	if st.num("details.events.process.exec") < 2 {
		t.Logf("events counted: %v", st.get("details.events"))
	}
}

func TestSpecialArgumentsKeepEveryLineParsable(t *testing.T) {
	d := newProgDir(t)
	a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}, CaptureArgv: true})
	root := d.start("pwtest-nginx", "args-special")
	child := intAfter(root.waitLine("child ", 10*time.Second), "pid")
	evs := a.waitEvents(10*time.Second, "child exit", func(evs []Ev) bool { return len(ofPID(evs, child)) >= 3 })
	raw, err := os.ReadFile(a.LogPath)
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		var v map[string]any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("line %d is not one JSON object: %v\n%q", i+1, err, line)
		}
	}
	exec := filterEv(ofPID(evs, child), func(e Ev) bool { return e.Type() == "process.exec" })[0]
	args := exec.argv()
	if len(args) != 5 || args[1] != "line1\nline2" || args[2] != `say "hi" <b>&</b>` || args[3] != "bad\uFFFD\uFFFDbytes" || args[4] != "tab\there" {
		t.Errorf("arguments %q", args)
	}
	if sanitized, _ := exec.get("data_quality.sanitized_fields").([]any); len(sanitized) != 1 || sanitized[0] != "process.argv" {
		t.Errorf("invalid UTF-8 must be flagged: %v", exec.get("data_quality.sanitized_fields"))
	}
	if !strings.Contains(string(raw), "<b>&</b>") {
		t.Error("HTML characters must not be escaped")
	}
}

func TestSequenceIncreasesAndOrderlyShutdown(t *testing.T) {
	d := newProgDir(t)
	a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}})
	root := d.startNode(recipe{Name: "pwtest-nginx", Children: []recipe{{Name: "pwtest-w", Mode: "sleep", Args: []string{"300"}}}})
	root.wait(10 * time.Second)
	a.waitEvents(10*time.Second, "health", func(evs []Ev) bool { return len(ofType(evs, "agent.health")) >= 1 })
	if code := a.Stop(); code != 0 {
		t.Fatalf("SIGTERM must end with exit code 0, got %d\n%s", code, a.stderr.String())
	}
	evs := a.Events()
	prev := 0
	for _, e := range evs {
		if e.Seq() <= prev {
			t.Fatalf("sequence not strictly increasing: %d after %d", e.Seq(), prev)
		}
		prev = e.Seq()
	}
	if evs[0].Type() != "agent.started" || evs[len(evs)-1].Type() != "agent.stopped" {
		t.Errorf("first %s last %s", evs[0].Type(), evs[len(evs)-1].Type())
	}
	if evs[len(evs)-1].str("details.reason") != "signal" {
		t.Errorf("reason %q", evs[len(evs)-1].str("details.reason"))
	}
	agentIDs := map[string]bool{}
	for _, e := range evs {
		agentIDs[e.str("agent_instance_id")] = true
	}
	if len(agentIDs) != 1 {
		t.Errorf("one run, one agent_instance_id: %v", agentIDs)
	}
}

func TestConfigurationErrorsStartNothing(t *testing.T) {
	requireAgentBinary(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "events.jsonl")
	bad := filepath.Join(dir, "bad.yaml")
	for name, tc := range map[string]struct {
		yaml string
		args []string
	}{
		"unknown key":      {"config_version: 1\nwatch:\n  image_contains: [x]\n  nope: 1\n", nil},
		"duplicate key":    {"config_version: 1\nwatch:\n  image_contains: [x]\n  image_contains: [y]\n", nil},
		"no watch pattern": {"config_version: 1\n", nil},
		"no version":       {"watch:\n  image_contains: [x]\n", nil},
		"broken regex":     {"config_version: 1\nwatch:\n  image_contains: [x]\nkill:\n  enabled: true\n  fields: [image]\n  strings: []\n  regex: [\"(\"]\n", nil},
	} {
		t.Run(name, func(t *testing.T) {
			os.WriteFile(bad, []byte(tc.yaml), 0o600)
			cmd := execCommand(agentBin, append([]string{"--config", bad, "--log-file", log}, tc.args...)...)
			out, _ := cmd.CombinedOutput()
			if code := cmd.ProcessState.ExitCode(); code != 2 {
				t.Fatalf("exit code %d, want 2:\n%s", code, out)
			}
			if _, err := os.Stat(log); err == nil {
				t.Fatal("a configuration error must not create the log file")
			}
		})
	}
	// check-config and print-config never attach, create files or signal.
	cmd := execCommand(agentBin, "check-config", "--watch-image-contains", "nginx", "--log-file", log)
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "configuration OK") {
		t.Fatalf("check-config: %v\n%s", err, out)
	}
	if _, err := os.Stat(log); err == nil {
		t.Fatal("check-config created a file")
	}
	cmd = execCommand(agentBin, "print-config", "--watch-image-contains", "nginx", "--log-file", log, "--webhook-url", "https://example.org/hook?token=SECRET")
	out, err := cmd.CombinedOutput()
	if err != nil || strings.Contains(string(out), "SECRET") || !strings.Contains(string(out), "image_contains") {
		t.Fatalf("print-config: %v\n%s", err, out)
	}
}

func TestWithoutPrivilegesTheAgentRefusesWithExitCode3(t *testing.T) {
	requireRoot(t)
	// A directory the unprivileged user can reach and write: t.TempDir sits in a 0700 parent.
	dir, err := os.MkdirTemp("", "pwnobody")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	a := &agent{t: t, dir: dir, stderr: &syncBuf{}}
	a.launch([]string{"--watch-image-contains", "x", "--log-file", filepath.Join(dir, "e.jsonl")}, &syscall.Credential{Uid: 65534, Gid: 65534})
	select {
	case <-a.done:
	case <-time.After(20 * time.Second):
		t.Fatal("agent did not exit")
	}
	if a.exit != 3 || !strings.Contains(a.stderr.String(), "privileges") {
		t.Fatalf("exit %d, stderr:\n%s", a.exit, a.stderr.String())
	}
}

func TestLogRotationKeepsEveryLine(t *testing.T) {
	d := newProgDir(t)
	a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}, RotateMB: 1, KeepFiles: 20, CaptureArgv: true})
	root := d.start("pwtest-nginx", "burst", "2500")
	root.collect("done ", 5*time.Minute)
	a.waitEvents(60*time.Second, "all exits", func(evs []Ev) bool { return len(ofType(evs, "process.exit")) >= 2500 })
	a.Stop()
	if _, err := os.Stat(a.LogPath + ".1"); err != nil {
		t.Fatalf("no rotation happened: %v", err)
	}
	evs := a.Events() // oldest archive first, then the active file
	prev := 0
	for _, e := range evs {
		if e.Seq() != prev+1 {
			t.Fatalf("sequence %d after %d: a line was lost or split by the rotation", e.Seq(), prev)
		}
		prev = e.Seq()
	}
	for i := 1; ; i++ {
		fi, err := os.Stat(a.LogPath + "." + strconv.Itoa(i))
		if err != nil {
			break
		}
		if fi.Mode().Perm() != 0o600 || fi.Size() > 1<<20+8192 {
			t.Errorf("archive %d: mode %v size %d", i, fi.Mode().Perm(), fi.Size())
		}
	}
}

func TestOnlyOneWriterPerLogAndNoSymlinks(t *testing.T) {
	requireRoot(t)
	a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}})
	second := execCommand(agentBin, "--watch-image-contains", "x", "--log-file", a.LogPath)
	out, _ := second.CombinedOutput()
	if code := second.ProcessState.ExitCode(); code != 1 || !strings.Contains(string(out), "lock") && !strings.Contains(string(out), "another") {
		t.Fatalf("second writer: exit %d\n%s", code, out)
	}
	// The first agent keeps writing undisturbed.
	if len(ofType(a.Events(), "agent.ready")) != 1 {
		t.Error("first agent disturbed")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real.jsonl")
	os.WriteFile(target, nil, 0o600)
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	sym := execCommand(agentBin, "--watch-image-contains", "x", "--log-file", link)
	out, _ = sym.CombinedOutput()
	if code := sym.ProcessState.ExitCode(); code != 1 || !strings.Contains(strings.ToLower(string(out)), "symlink") {
		t.Fatalf("symlink as log file: exit %d\n%s", code, out)
	}
}

// TestOverloadIsMeasuredAndReported freezes the agent while thousands of
// processes come and go, so the small ring buffer overflows: the loss must be
// counted in the kernel, reported as agent.gap and visible in the health data,
// and the agent must keep working afterwards.
func TestOverloadIsMeasuredAndReported(t *testing.T) {
	d := newProgDir(t)
	a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}, RingMB: 1, Reconcile: "1s"})
	agentPID := a.cmd.Process.Pid
	if err := syscall.Kill(agentPID, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	resumed := false
	defer func() {
		if !resumed {
			syscall.Kill(agentPID, syscall.SIGCONT)
		}
	}()
	const n = 6000
	root := d.start("pwtest-nginx", "burst", strconv.Itoa(n))
	root.collect("done ", 5*time.Minute)
	syscall.Kill(agentPID, syscall.SIGCONT)
	resumed = true

	evs := a.waitEvents(60*time.Second, "the gap report", func(evs []Ev) bool { return len(ofType(evs, "agent.gap")) > 0 })
	gap := ofType(evs, "agent.gap")[0]
	if gap.str("details.cause") != "ring_buffer_full" || gap.num("details.lost_total") <= 0 || gap.get("data_quality.collection_gap") != true {
		t.Fatalf("gap %v", gap.Raw["details"])
	}
	// The agent works on: a new tree after the overload is observed completely.
	post := d.startNode(recipe{Name: "pwtest-nginx", Children: []recipe{{Name: "pwtest-after", Mode: "sleep", Args: []string{"300"}}}})
	post.wait(10 * time.Second)
	a.waitEvents(30*time.Second, "tree after the overload", func(evs []Ev) bool {
		return len(filterEv(ofType(evs, "process.exit"), func(e Ev) bool { return e.Image() == "pwtest-after" })) > 0
	})
	a.Stop()
	stopped := ofType(a.Events(), "agent.stopped")[0]
	lost := stopped.num("details.collector.lost_total")
	forkRecords := stopped.num("details.collector.records.fork")
	lostFork := stopped.num("details.collector.lost.fork")
	if lost <= 0 {
		t.Fatalf("the kernel counted no loss: %v", stopped.Raw["details"])
	}
	// Every child fork either reached the ring buffer or was counted as lost.
	if forkRecords+lostFork < n {
		t.Errorf("forks submitted %d + lost %d < %d generated: a loss is not counted", forkRecords, lostFork, n)
	}
	got := len(ofType(a.Events(), "process.fork"))
	t.Logf("generated %d children: kernel submitted %d fork records, lost %d (all types lost %d); %d fork events in the log",
		n, forkRecords, lostFork, lost, got)
}

// A process that already has a living child execs into a watched program: it
// becomes a root, and the child (whose fork nobody associated with a tree) is
// discovered by the reconciliation that the new root triggers.
func TestLivingChildrenOfANewRootAreDiscovered(t *testing.T) {
	d := newProgDir(t, "pwtest-nginx", "pwtest-preexisting-child")
	a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}})
	p := d.start("pwtest-pre", "fork-then-exec", "pwtest-preexisting-child", "pwtest-nginx")
	child := intAfter(p.waitLine("child ", 10*time.Second), "pid")
	evs := a.waitEvents(15*time.Second, "the discovery of the pre-existing child", func(evs []Ev) bool {
		return len(filterEv(ofPID(evs, child), func(e Ev) bool { return e.Type() == "process.discovered" })) > 0
	})
	root := filterEv(ofType(evs, "process.exec"), func(e Ev) bool { return e.PID() == p.PID && e.Role() == "root" })
	if len(root) != 1 || root[0].Image() != "pwtest-nginx" {
		t.Fatalf("the exec into the watched program creates the root:\n%s", summarize(evs, 20))
	}
	disc := filterEv(ofPID(evs, child), func(e Ev) bool { return e.Type() == "process.discovered" })[0]
	if disc.Role() != "descendant" || disc.RootPID() != p.PID || disc.Depth() != 1 || disc.str("details.discovery") != "reconcile" {
		t.Errorf("discovered child: role %s root %d depth %d (%s)", disc.Role(), disc.RootPID(), disc.Depth(), disc.str("details.discovery"))
	}
	if n := len(filterEv(ofPID(evs, child), func(e Ev) bool { return e.Type() == "process.fork" })); n != 0 {
		t.Errorf("a discovery is never reported as an invented fork (%d fork events)", n)
	}
}

// nginx -> excluded helper -> sh -> curl: the helper's own events are excluded,
// the shell and curl below it stay visible and keep the root.
func TestExcludedHelperDoesNotHideItsDescendants(t *testing.T) {
	d := newProgDir(t)
	a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}, ExcludeImage: []string{"pwtest-excluded"}})
	root := d.startNode(recipe{Name: "pwtest-nginx", Children: []recipe{
		{Name: "pwtest-excluded", Children: []recipe{
			{Name: "pwtest-sh", Children: []recipe{{Name: "pwtest-curl", Mode: "sleep", Args: []string{"500"}}}},
		}},
	}})
	root.wait(15 * time.Second)
	evs := a.waitEvents(10*time.Second, "curl exit", func(evs []Ev) bool {
		return len(filterEv(ofType(evs, "process.exit"), func(e Ev) bool { return e.Image() == "pwtest-curl" })) > 0
	})
	var excluded, visible []string
	for _, e := range evs {
		if !strings.HasPrefix(e.Type(), "process.") {
			continue
		}
		if e.get("filter.excluded") == true {
			excluded = append(excluded, e.Type()+":"+e.Image())
			if m, _ := e.get("filter.matches").([]any); len(m) != 1 {
				t.Errorf("an excluded event names the matching string: %v", e.get("filter.matches"))
			}
		} else {
			visible = append(visible, e.Type()+":"+e.Image())
		}
	}
	// The exec into the excluded program and the fork of its child (inherited image) are excluded.
	hasPrefix := func(list []string, p string) bool {
		for _, s := range list {
			if strings.HasPrefix(s, p) {
				return true
			}
		}
		return false
	}
	if !hasPrefix(excluded, "process.exec:pwtest-excluded") || !hasPrefix(excluded, "process.fork:pwtest-excluded") {
		t.Errorf("excluded events: %v", excluded)
	}
	for _, name := range []string{"pwtest-sh", "pwtest-curl"} {
		if !hasPrefix(visible, "process.exec:"+name) {
			t.Errorf("%s must remain visible: %v", name, visible)
		}
		e := filterEv(ofType(evs, "process.exec"), func(e Ev) bool { return e.Image() == name })[0]
		if e.RootPID() != root.PID {
			t.Errorf("%s root %d, want %d", name, e.RootPID(), root.PID)
		}
	}
}
