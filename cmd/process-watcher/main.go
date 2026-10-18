// Command process-watcher observes the process trees of programs whose image
// name contains a configured substring and logs process creation, successful
// exec and process end as JSONL.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/Neo23x0/process-watcher/internal/app"
	"github.com/Neo23x0/process-watcher/internal/config"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

func realMain(args []string, stdout, stderr io.Writer) int {
	r, err := config.Resolve(args, config.OSEnv())
	if err != nil {
		var ue *config.UsageError
		if errors.As(err, &ue) {
			fmt.Fprintf(stderr, "process-watcher: %v\nTry 'process-watcher --help'.\n", err)
		} else {
			fmt.Fprintf(stderr, "process-watcher: configuration error: %v\n", err)
		}
		return app.ExitConfig
	}

	switch r.Command {
	case config.CommandHelp:
		fmt.Fprint(stdout, config.Usage())
		return app.ExitOK
	case config.CommandVersion:
		fmt.Fprintf(stdout, "process-watcher %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return app.ExitOK
	case config.CommandCheckConfig:
		// Pure validation: no signals, no BPF, no network, nothing is created. The
		// only file besides the configuration that is read is the CA bundle.
		src := r.SourceFile
		if src == "" {
			src = "built-in defaults"
		}
		if err := config.CheckFiles(r.Config, config.OSEnv()); err != nil {
			fmt.Fprintf(stderr, "process-watcher: configuration error: %v\n", err)
			return app.ExitConfig
		}
		fmt.Fprintf(stdout, "configuration OK (%s)\n", src)
		if r.Config.Kill.Enabled {
			mode := "active: matching descendants are sent SIGKILL when run"
			if r.Config.Kill.DryRun {
				mode = "dry run: decisions are logged, no signal is sent"
			}
			fmt.Fprintf(stdout, "kill rules: %d string(s), %d regex(es), fields %v; %s\n",
				len(r.Config.Kill.Strings), len(r.Config.Kill.Regex), r.Config.Kill.Fields, mode)
			fmt.Fprintln(stdout, "check-config never sends a signal.")
			for _, w := range app.KillWarnings(r.Config) {
				fmt.Fprintf(stdout, "warning: %s\n", w)
			}
		}
		return app.ExitOK
	case config.CommandPrintConfig:
		if err := config.PrintConfig(stdout, r); err != nil {
			fmt.Fprintf(stderr, "process-watcher: %v\n", err)
			return app.ExitRuntime
		}
		return app.ExitOK
	case config.CommandDoctor:
		return app.Doctor(r, version, stdout)
	}

	// Like every other configuration error, an unusable CA bundle ends the run
	// with exit code 2 before platform checks, log files or sockets are touched.
	if err := config.CheckFiles(r.Config, config.OSEnv()); err != nil {
		fmt.Fprintf(stderr, "process-watcher: configuration error: %v\n", err)
		return app.ExitConfig
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		// After the first signal the orderly shutdown runs; a second one ends
		// the process at once (default signal behaviour is restored).
		<-ctx.Done()
		stop()
	}()
	return app.Run(ctx, r, app.Options{Version: version, Stderr: stderr})
}
