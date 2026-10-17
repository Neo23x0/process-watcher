//go:build linux

package ebpf

// Preflight runs the cheap prerequisite checks (architecture, privileges,
// initial PID namespace, kernel BTF) without loading anything, so the agent
// can refuse to start before it has any side effect such as creating the log.
func Preflight() error {
	if err := checkEnvironment(); err != nil {
		return err
	}
	return checkKernelBTF()
}
