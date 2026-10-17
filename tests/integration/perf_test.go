//go:build linux

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func init() {
	// spin <ms>: start /bin/true children one after the other until the time is up.
	extraHelpers["spin"] = func(args []string) {
		ms, _ := strconv.Atoi(args[0])
		end := time.Now().Add(time.Duration(ms) * time.Millisecond)
		n := 0
		for time.Now().Before(end) {
			if err := exec.Command("/bin/true").Run(); err != nil {
				break
			}
			n++
		}
		say("spun n=%d", n)
	}
}

// procCPU returns the user+system CPU seconds and the peak RSS in KiB of a process.
func procCPU(t *testing.T, pid int) (cpu float64, hwmKiB int) {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+2:])
	ut, _ := strconv.ParseFloat(f[11], 64)
	st, _ := strconv.ParseFloat(f[12], 64)
	status, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	for _, l := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(l, "VmHWM:"); ok {
			hwmKiB, _ = strconv.Atoi(strings.Fields(v)[0])
		}
	}
	return (ut + st) / 100.0, hwmKiB
}

func procRSSKiB(pid int) int {
	status, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	for _, l := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(l, "VmRSS:"); ok {
			n, _ := strconv.Atoi(strings.Fields(v)[0])
			return n
		}
	}
	return 0
}

func percentiles(v []float64) map[string]float64 {
	if len(v) == 0 {
		return nil
	}
	sort.Float64s(v)
	at := func(p float64) float64 { return v[int(p*float64(len(v)-1))] }
	var sum float64
	for _, x := range v {
		sum += x
	}
	return map[string]float64{"min": v[0], "avg": sum / float64(len(v)), "p50": at(0.5), "p95": at(0.95), "p99": at(0.99), "max": v[len(v)-1]}
}

type perfPhase struct {
	Name            string  `json:"name"`
	Seconds         float64 `json:"seconds"`
	AgentCPUSeconds float64 `json:"agent_cpu_seconds"`
	AgentCPUPercent float64 `json:"agent_cpu_percent_of_one_core"`
	AgentRSSPeakMiB float64 `json:"agent_rss_peak_mib"`
	AgentRSSMiB     float64 `json:"agent_rss_end_mib"`
	Spawns          int     `json:"processes_spawned"`
	SpawnsPerSecond float64 `json:"spawns_per_second"`
	// EventsWritten counts the process events the agent wrote in this phase
	// (agent.stopped, details.events); the file keeps only keep_files archives,
	// so LogEventsOnDisk is smaller under a heavy load.
	EventsWritten       int                `json:"process_events_written"`
	EventsWrittenPerSec float64            `json:"process_events_written_per_second"`
	LogEventsOnDisk     int                `json:"log_events_still_on_disk"`
	KernelRecords       int                `json:"kernel_records_submitted"`
	KernelLost          int                `json:"kernel_records_lost"`
	LatencyMs           map[string]float64 `json:"latency_observed_minus_timestamp_ms,omitempty"`
}

// TestMeasureResourcesAndThroughput measures CPU, memory, throughput and the
// delay between a kernel event and its processing (observed_at - timestamp in
// the log) while idle and under a fork/exec load inside and outside of the
// observed tree. It prints the numbers and writes them to
// $PW_E2E_REPORT_DIR/perf.json. Numbers from emulated CPUs are meaningless;
// run it on real or virtualized hardware.
func TestMeasureResourcesAndThroughput(t *testing.T) {
	if os.Getenv("PW_E2E_PERF") == "" {
		t.Skip("set PW_E2E_PERF=1 to run the measurements")
	}
	requireRoot(t)
	secs := 10
	if v, err := strconv.Atoi(os.Getenv("PW_E2E_PERF_SECONDS")); err == nil && v > 0 {
		secs = v
	}
	workers := runtime.NumCPU() / 2
	if workers < 1 {
		workers = 1
	}
	var report []perfPhase

	for _, mode := range []struct {
		name   string
		argv   bool
		inTree bool
		idle   bool
	}{
		{"idle", false, false, true},
		{"load outside the observed tree (filtering only)", false, false, false},
		{"load inside the observed tree", false, true, false},
		{"load inside the observed tree, argv capture on", true, true, false},
	} {
		d := newProgDir(t)
		a := startAgent(t, agentCfg{Watch: []string{"pwtest-nginx"}, CaptureArgv: mode.argv, Health: "1h", Reconcile: "1h"})
		pid := a.cmd.Process.Pid
		time.Sleep(500 * time.Millisecond)
		cpu0, _ := procCPU(t, pid)
		start := time.Now()
		spawns := 0
		if mode.idle {
			time.Sleep(time.Duration(secs) * time.Second)
		} else {
			var progs []*prog
			for i := 0; i < workers; i++ {
				name := "pwtest-other"
				if mode.inTree {
					name = "pwtest-nginx" // every spinner is itself a root of the observed tree
				}
				progs = append(progs, d.start(name, "spin", strconv.Itoa(secs*1000)))
			}
			var wg sync.WaitGroup
			var mu sync.Mutex
			for _, p := range progs {
				wg.Add(1)
				go func(p *prog) {
					defer wg.Done()
					deadline := time.After(time.Duration(secs+60) * time.Second)
					for {
						select {
						case l, ok := <-p.lines:
							if !ok {
								return
							}
							if strings.HasPrefix(l, "spun ") {
								mu.Lock()
								spawns += intAfter(l, "n")
								mu.Unlock()
							}
						case <-deadline:
							return
						}
					}
				}(p)
			}
			wg.Wait()
		}
		elapsed := time.Since(start).Seconds()
		cpu1, hwm := procCPU(t, pid)
		rss := procRSSKiB(pid)
		time.Sleep(500 * time.Millisecond)
		a.Stop()
		evs := a.Events()
		stopped := ofType(evs, "agent.stopped")[0]
		ph := perfPhase{
			Name: mode.name, Seconds: elapsed, AgentCPUSeconds: cpu1 - cpu0, AgentCPUPercent: 100 * (cpu1 - cpu0) / elapsed,
			AgentRSSPeakMiB: float64(hwm) / 1024, AgentRSSMiB: float64(rss) / 1024, Spawns: spawns, SpawnsPerSecond: float64(spawns) / elapsed,
			LogEventsOnDisk: len(evs),
			KernelRecords:   stopped.num("details.collector.records.fork") + stopped.num("details.collector.records.exec") + stopped.num("details.collector.records.exit"),
			KernelLost:      stopped.num("details.collector.lost_total"),
		}
		if m, ok := stopped.get("details.events").(map[string]any); ok {
			for k, v := range m {
				if f, isNum := v.(float64); isNum && strings.HasPrefix(k, "process.") {
					ph.EventsWritten += int(f)
				}
			}
			ph.EventsWrittenPerSec = float64(ph.EventsWritten) / elapsed
		}
		var lat []float64
		for _, e := range evs {
			if e.str("source") != "ebpf" {
				continue
			}
			ts, err1 := time.Parse(time.RFC3339Nano, e.str("timestamp"))
			ob, err2 := time.Parse(time.RFC3339Nano, e.str("observed_at"))
			if err1 == nil && err2 == nil {
				lat = append(lat, float64(ob.Sub(ts))/1e6)
			}
		}
		ph.LatencyMs = percentiles(lat)
		report = append(report, ph)
		b, _ := json.Marshal(ph)
		t.Logf("%s", b)
	}
	if dir := os.Getenv("PW_E2E_REPORT_DIR"); dir != "" {
		os.MkdirAll(dir, 0o755)
		out := map[string]any{"cpus": runtime.NumCPU(), "arch": runtime.GOARCH, "workers": workers, "phases": report}
		b, _ := json.MarshalIndent(out, "", "  ")
		os.WriteFile(filepath.Join(dir, "perf.json"), b, 0o644)
	}
	_ = fmt.Sprint
	_ = syscall.SIGTERM
}
