package config

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// DefaultFileName is the name of the configuration file searched in the
// working directory and next to the binary.
const DefaultFileName = "process-watcher.yaml"

// Command is the action selected on the command line.
type Command string

// The subcommands; CommandRun is the default when none is given.
const (
	CommandRun         Command = "run"
	CommandCheckConfig Command = "check-config"
	CommandPrintConfig Command = "print-config"
	CommandDoctor      Command = "doctor"
)

// CommandHelp and CommandVersion are returned for --help/-h and --version;
// the caller prints Usage() or the version and exits with 0.
const (
	CommandHelp    Command = "help"
	CommandVersion Command = "version"
)

var subcommands = []Command{CommandRun, CommandCheckConfig, CommandPrintConfig, CommandDoctor}

func commandByName(s string) (Command, bool) {
	for _, c := range subcommands {
		if string(c) == s {
			return c, true
		}
	}
	return "", false
}

func commandNames() string {
	names := make([]string, len(subcommands))
	for i, c := range subcommands {
		names[i] = string(c)
	}
	return strings.Join(names, ", ")
}

// Resolved is the outcome of Resolve.
type Resolved struct {
	Command Command
	// Config is the merged and validated configuration. Relative file paths
	// (outputs.file.path, outputs.tcp.ca_file) are cleaned absolute paths.
	// For CommandHelp and CommandVersion it holds the defaults.
	Config Config
	// SourceFile is the absolute path of the YAML file that was loaded, or ""
	// when the built-in defaults are used.
	SourceFile string
	// Cwd is the working directory relative paths were resolved against.
	Cwd string
}

// Resolve turns a command line (without the program name, i.e. os.Args[1:])
// into a validated configuration.
//
// The precedence is built-in defaults < one YAML file < explicitly set flags.
// The YAML file is searched in this order: --config (which must exist), then
// DefaultFileName in the working directory, then DefaultFileName next to the
// real binary (symlinks resolved); duplicate candidates are tried once and a
// file that exists but is unreadable or invalid is an error, never skipped.
//
// For CommandRun and CommandCheckConfig the bearer token variable named by
// outputs.webhook.token_env must be set; the token itself is not kept (see
// ResolveWebhookToken). CommandDoctor does not require a watch pattern; all
// other commands do.
//
// Malformed command lines yield *UsageError, configuration problems *Error
// (several may be joined with errors.Join). Both map to exit code 2. Resolve
// returns early with CommandHelp or CommandVersion without reading any
// configuration file.
func Resolve(args []string, env Env) (*Resolved, error) {
	cl, err := parseArgs(args)
	if err != nil {
		return nil, err
	}
	switch {
	case cl.help:
		return &Resolved{Command: CommandHelp, Config: Default()}, nil
	case cl.version:
		return &Resolved{Command: CommandVersion, Config: Default()}, nil
	}

	cwd, cerr := workingDir(env)
	if cerr != nil {
		return nil, cerr
	}
	src, ferr := findConfig(env, cwd, cl.config)
	if ferr != nil {
		return nil, ferr
	}

	res := &Resolved{Command: cl.command, Cwd: cwd}
	cfg := Default()
	origins := map[string]origin{}
	if src != nil {
		res.SourceFile = src.path
		var errs []*Error
		if cfg, origins, errs = loadYAML(src.path, src.data, cfg); len(errs) > 0 {
			return nil, joinErrors(errs)
		}
	}
	if errs := applyFlags(&cfg, cl, origins); len(errs) > 0 {
		return nil, joinErrors(errs)
	}
	normalize(&cfg)

	if errs := validate(&cfg, cl.command != CommandDoctor); len(errs) > 0 {
		decorate(errs, origins)
		return nil, joinErrors(errs)
	}
	cfg.Outputs.File.Path = absPath(cwd, cfg.Outputs.File.Path)
	cfg.Outputs.TCP.CAFile = absPath(cwd, cfg.Outputs.TCP.CAFile)

	if cl.command == CommandRun || cl.command == CommandCheckConfig {
		if _, terr := ResolveWebhookToken(cfg, env.Getenv); terr != nil {
			var e *Error
			if errors.As(terr, &e) {
				decorate([]*Error{e}, origins)
			}
			return nil, terr
		}
	}
	res.Config = cfg
	return res, nil
}

// CheckFiles verifies the files the configuration refers to: a configured CA
// bundle (outputs.tcp.ca_file) must be readable and hold at least one
// certificate. Resolve never reads them, so that parsing and validation work
// without a file system; check-config calls CheckFiles, and run reports the
// same problems before it creates anything. Nothing is connected to.
func CheckFiles(cfg Config, env Env) error {
	t := cfg.Outputs.TCP
	if !t.TLS || t.CAFile == "" {
		return nil
	}
	const path = "outputs.tcp.ca_file"
	pem, err := env.readFile(t.CAFile)
	if err != nil {
		return errorf(path, "cannot read the CA file: %v", err)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(pem) {
		return errorf(path, "%s contains no valid PEM certificate", t.CAFile)
	}
	return nil
}

// ResolveWebhookToken returns the bearer token for the webhook. It returns ""
// without error when the webhook has no token_env or no URL. A token_env
// whose variable is unset, empty or not a usable header value is a
// configuration error; messages name the variable, never its value.
func ResolveWebhookToken(cfg Config, getenv func(string) string) (string, error) {
	w := cfg.Outputs.Webhook
	if w.URL == "" || w.TokenEnv == "" {
		return "", nil
	}
	var token string
	if getenv != nil {
		token = getenv(w.TokenEnv)
	}
	const path = "outputs.webhook.token_env"
	switch {
	case token == "":
		return "", errorf(path, "environment variable %s is not set or empty", w.TokenEnv)
	case strings.ContainsFunc(token, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return "", errorf(path, "environment variable %s contains control characters (for example a trailing newline)", w.TokenEnv)
	}
	return token, nil
}

func workingDir(env Env) (string, *Error) {
	if env.Getwd == nil {
		return "", errorf("", "cannot determine the working directory")
	}
	cwd, err := env.Getwd()
	if err != nil {
		return "", errorf("", "cannot determine the working directory: %v", err)
	}
	if !filepath.IsAbs(cwd) {
		return "", errorf("", "the working directory %q is not an absolute path", cwd)
	}
	return filepath.Clean(cwd), nil
}

// absPath resolves a relative path against cwd and cleans the result. An
// empty path stays empty.
func absPath(cwd, p string) string {
	if p == "" {
		return ""
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	return filepath.Clean(p)
}

// source is a configuration file that was found and read.
type source struct {
	path string
	data []byte
}

// findConfig implements the configuration file search. It returns a nil
// source when no file exists and the built-in defaults apply.
func findConfig(env Env, cwd string, explicit *rawValue) (*source, *Error) {
	if explicit != nil {
		raw := explicit.vals[len(explicit.vals)-1]
		if raw == "" {
			return nil, errorf("--config", "the path must not be empty")
		}
		path := absPath(cwd, raw)
		data, err := readConfigFile(env, path)
		if err != nil {
			return nil, errorf("--config", "cannot use configuration file: %v", err)
		}
		return &source{path: path, data: data}, nil
	}
	for _, path := range candidatePaths(env, cwd) {
		data, err := readConfigFile(env, path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, &Error{File: path, Msg: fmt.Sprintf("cannot read configuration file: %v", err)}
		}
		return &source{path: path, data: data}, nil
	}
	return nil, nil
}

// candidatePaths lists the implicit configuration file locations without
// duplicates: the working directory first, then the directory of the real
// binary.
func candidatePaths(env Env, cwd string) []string {
	paths := []string{filepath.Join(cwd, DefaultFileName)}
	if dir, ok := binaryDir(env, cwd); ok {
		if p := filepath.Join(dir, DefaultFileName); p != paths[0] {
			paths = append(paths, p)
		}
	}
	return paths
}

// binaryDir returns the directory of the running binary after resolving
// symlinks. ok is false if it cannot be determined.
func binaryDir(env Env, cwd string) (dir string, ok bool) {
	if env.Executable == nil {
		return "", false
	}
	exe, err := env.Executable()
	if err != nil || exe == "" {
		return "", false
	}
	if !filepath.IsAbs(exe) {
		exe = filepath.Join(cwd, exe)
	}
	real, err := env.evalSymlinks(exe)
	if err != nil {
		return "", false
	}
	return filepath.Dir(real), true
}

// readConfigFile reads a regular file of bounded size.
func readConfigFile(env Env, path string) ([]byte, error) {
	info, err := env.stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := env.readFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxFileBytes)
	}
	return data, nil
}

// decorate adds the file/line or flag origin of the offending value to errors.
func decorate(errs []*Error, origins map[string]origin) {
	for _, e := range errs {
		if e.File != "" || e.Flag != "" {
			continue
		}
		o, ok := origins[e.Path]
		if !ok {
			base, _, _ := strings.Cut(e.Path, "[")
			o, ok = origins[base]
		}
		switch {
		case !ok:
		case o.flag != "":
			e.Flag = o.flag
		default:
			e.File, e.Line = o.file, o.line
		}
	}
}
