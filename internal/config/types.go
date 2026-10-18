// Package config loads, merges and validates the process-watcher configuration.
//
// The YAML schema is defined by the types in this file. Every leaf has an
// equivalent CLI flag (see flags.go); precedence is built-in defaults < YAML
// file < explicitly set flags.
package config

import "time"

// CurrentVersion is the only supported value of config_version.
const CurrentVersion = 1

// Values of ExcludeConfig.Scope.
const (
	ScopeRemote = "remote"
	ScopeAll    = "all"
)

// Values of KillConfig.Fields.
const (
	KillFieldImage     = "image"
	KillFieldImagePath = "image_path"
	KillFieldArgv      = "argv"
)

// Config is the complete, merged configuration.
type Config struct {
	ConfigVersion int            `yaml:"config_version"`
	Watch         WatchConfig    `yaml:"watch"`
	Exclude       ExcludeConfig  `yaml:"exclude"`
	Capture       CaptureConfig  `yaml:"capture"`
	Kill          KillConfig     `yaml:"kill"`
	Outputs       OutputsConfig  `yaml:"outputs"`
	Delivery      DeliveryConfig `yaml:"delivery"`
	Runtime       RuntimeConfig  `yaml:"runtime"`
}

// WatchConfig selects the processes whose trees are observed. Entries are
// literal substrings of the executed image file name, combined with OR.
type WatchConfig struct {
	ImageContains []string `yaml:"image_contains"`
	IgnoreCase    bool     `yaml:"ignore_case"`
	// MaxDepth limits the depth of emitted process events; 0 means unlimited.
	MaxDepth int `yaml:"max_depth"`
}

// ExcludeConfig suppresses process events (never the internal tracking).
type ExcludeConfig struct {
	ImageContains []string `yaml:"image_contains"`
	ArgvContains  []string `yaml:"argv_contains"`
	// Scope is ScopeRemote (default) or ScopeAll.
	Scope string `yaml:"scope"`
}

// CaptureConfig controls optional, potentially sensitive data capture.
type CaptureConfig struct {
	Argv bool `yaml:"argv"`
	// ArgvMaxArgs and ArgvMaxBytes limit the argument capture per exec: at most
	// that many arguments and that many raw bytes (arguments plus NUL
	// terminators). They only apply with Argv.
	ArgvMaxArgs  int `yaml:"argv_max_args"`
	ArgvMaxBytes int `yaml:"argv_max_bytes"`
}

// KillConfig describes the optional rule based termination of observed
// descendant processes. It is disabled by default.
type KillConfig struct {
	Enabled bool `yaml:"enabled"`
	DryRun  bool `yaml:"dry_run"`
	// Fields lists the matched fields: image, image_path, argv.
	Fields []string `yaml:"fields"`
	// Strings are literal, case-sensitive substrings (strings.Contains).
	Strings []string `yaml:"strings"`
	// Regex are Go regular expressions (regexp.MatchString, unanchored).
	Regex []string `yaml:"regex"`
	// SpareRootImage never kills a descendant whose executable is the same file
	// as the one of its root. A service master forks workers (and re-executes
	// itself on a reload) with that image, so a rule that matches the service's
	// own name would otherwise kill the service. Off by default.
	SpareRootImage bool `yaml:"spare_root_image"`
}

// OutputsConfig groups the local file and the optional remote outputs.
type OutputsConfig struct {
	File    FileOutput    `yaml:"file"`
	TCP     TCPOutput     `yaml:"tcp"`
	UDP     UDPOutput     `yaml:"udp"`
	Webhook WebhookOutput `yaml:"webhook"`
}

// FileOutput configures the mandatory local JSONL log.
type FileOutput struct {
	Path string `yaml:"path"`
	// RotateSizeMB is in MiB (1 048 576 bytes).
	RotateSizeMB int           `yaml:"rotate_size_mb"`
	KeepFiles    int           `yaml:"keep_files"`
	SyncInterval time.Duration `yaml:"sync_interval"`
}

// TCPOutput configures the optional TCP target; an empty Address disables it.
type TCPOutput struct {
	Address    string `yaml:"address"`
	TLS        bool   `yaml:"tls"`
	CAFile     string `yaml:"ca_file"`
	ServerName string `yaml:"server_name"`
}

// UDPOutput configures the optional UDP target; an empty Address disables it.
type UDPOutput struct {
	Address  string `yaml:"address"`
	MaxBytes int    `yaml:"max_bytes"`
}

// WebhookOutput configures the optional webhook; an empty URL disables it.
type WebhookOutput struct {
	URL string `yaml:"url"`
	// TokenEnv names an environment variable holding a bearer token.
	TokenEnv string        `yaml:"token_env"`
	Timeout  time.Duration `yaml:"timeout"`
}

// DeliveryConfig applies to all remote outputs.
type DeliveryConfig struct {
	QueueSize      int           `yaml:"queue_size"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
	WriteTimeout   time.Duration `yaml:"write_timeout"`
	MaxRetries     int           `yaml:"max_retries"`
}

// RuntimeConfig holds resource and lifecycle limits.
type RuntimeConfig struct {
	// RingBufferMB is in MiB and must be a power of two.
	RingBufferMB      int           `yaml:"ring_buffer_mb"`
	MaxProcesses      int           `yaml:"max_processes"`
	HealthInterval    time.Duration `yaml:"health_interval"`
	ReconcileInterval time.Duration `yaml:"reconcile_interval"`
	ShutdownTimeout   time.Duration `yaml:"shutdown_timeout"`
}
