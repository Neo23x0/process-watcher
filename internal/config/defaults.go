package config

import "time"

// Default returns the built-in defaults. The watch list is intentionally
// empty: a normal run requires at least one watch pattern.
func Default() Config {
	return Config{
		ConfigVersion: CurrentVersion,
		Watch: WatchConfig{
			ImageContains: []string{},
		},
		Exclude: ExcludeConfig{
			ImageContains: []string{},
			ArgvContains:  []string{},
			Scope:         ScopeRemote,
		},
		Capture: CaptureConfig{
			ArgvMaxArgs:  32,
			ArgvMaxBytes: 4096,
		},
		Kill: KillConfig{
			Fields:  []string{KillFieldImage},
			Strings: []string{},
			Regex:   []string{},
		},
		Outputs: OutputsConfig{
			File: FileOutput{
				Path:         "./process-watcher.jsonl",
				RotateSizeMB: 100,
				KeepFiles:    5,
				SyncInterval: time.Second,
			},
			UDP:     UDPOutput{MaxBytes: 8192},
			Webhook: WebhookOutput{Timeout: 10 * time.Second},
		},
		Delivery: DeliveryConfig{
			QueueSize:      10000,
			ConnectTimeout: 5 * time.Second,
			WriteTimeout:   5 * time.Second,
			MaxRetries:     5,
		},
		Runtime: RuntimeConfig{
			RingBufferMB:      16,
			MaxProcesses:      65536,
			HealthInterval:    60 * time.Second,
			ReconcileInterval: 30 * time.Second,
			ShutdownTimeout:   10 * time.Second,
		},
	}
}
