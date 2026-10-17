//go:build linux

package ebpf

import (
	"regexp"
	"strconv"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// verifierInsnBudget is how many instructions the verifier may process per
// program in this test. The kernel stops at 1,000,000 (BPF_COMPLEXITY_LIMIT_INSNS)
// and Linux 5.15, whose pruning is the least effective of the supported
// kernels, needs about 21,000 for the largest program; before the path walk
// became a global function it needed 817,000 and failed on kernels with the
// slightest difference. The budget fails the test long before the kernel
// limit comes into view.
const verifierInsnBudget = 100_000

var processedRE = regexp.MustCompile(`processed (\d+) insns`)

// TestVerifierComplexity loads every program in the configurations the agent
// can request and reports how many instructions the verifier of this kernel
// processed. A program that grows towards the kernel's limit would be rejected
// on other kernels without any change of the source.
func TestVerifierComplexity(t *testing.T) {
	requireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	pidMax, err := readPidMax()
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []struct {
		name       string
		args, live bool
	}{
		{"defaults", false, false},
		{"capture_args", true, false},
		{"live_table", false, true},
		{"capture_args+live_table", true, true},
	} {
		t.Run(cfg.name, func(t *testing.T) {
			spec, err := loadPw()
			if err != nil {
				t.Fatal(err)
			}
			spec.Maps[pwMapPwEvents].MaxEntries = 1 << 20
			vars := map[string]uint32{}
			if cfg.args {
				vars[pwVarCfgCaptureArgs] = 1
			}
			if cfg.live {
				spec.Maps[pwMapPwLive].MaxEntries = pidMax
				vars[pwVarCfgLiveTable] = 1
				vars[pwVarCfgLiveSize] = pidMax
			}
			for name, v := range vars {
				if err := spec.Variables[name].Set(v); err != nil {
					t.Fatalf("set %s: %v", name, err)
				}
			}
			coll, err := cebpf.NewCollectionWithOptions(spec, cebpf.CollectionOptions{
				Programs: cebpf.ProgramOptions{LogLevel: cebpf.LogLevelStats},
			})
			if err != nil {
				t.Fatalf("load: %v", classifyLoadError(err))
			}
			defer coll.Close()

			for _, name := range []string{pwProgPwSchedProcessFork, pwProgPwSchedProcessExec, pwProgPwSchedProcessExit, pwProgPwDumpTask} {
				prog := coll.Programs[name]
				if prog == nil {
					t.Fatalf("program %s missing", name)
				}
				m := processedRE.FindStringSubmatch(prog.VerifierLog)
				if m == nil {
					t.Logf("%s: the kernel returned no verifier statistics", name)
					continue
				}
				n, _ := strconv.Atoi(m[1])
				t.Logf("%s: %d instructions processed by the verifier (kernel limit 1000000, budget %d)", name, n, verifierInsnBudget)
				if n > verifierInsnBudget {
					t.Errorf("%s: verifier processed %d instructions, budget is %d", name, n, verifierInsnBudget)
				}
			}
		})
	}
}
