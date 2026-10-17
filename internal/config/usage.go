package config

import (
	"strings"
)

const usageIntro = `process-watcher observes the process trees of selected programs on Linux (eBPF) and
logs process creation, program changes and process exit as JSONL.

Usage:
  process-watcher [run] [flags]          observe processes (the default command)
  process-watcher check-config [flags]   load and validate the configuration, then exit
  process-watcher print-config [flags]   print the resolved configuration as YAML, then exit
  process-watcher doctor [flags]         check kernel features and permissions
  process-watcher --help | -h            show this help
  process-watcher --version              show the version

check-config and print-config attach no BPF programs, create no output files, contact no remote
endpoint and never send signals. print-config shows the source file and redacts the query values
of the webhook URL; of the bearer token it shows only the variable name.
doctor needs no watch pattern. run needs root privileges.

Flags may appear before or after the subcommand and are written -flag or --flag, with the value
as --flag value or --flag=value. A boolean flag alone means true; to set it to false write
--flag=false (a separate argument is not taken as its value).

Configuration:
  Every YAML setting has an equivalent flag; each flag below names its YAML key and default.
  Precedence: built-in defaults < YAML file < explicitly set flags. Environment variables are
  not a configuration layer; only the variable named by --webhook-token-env is read.

  Flags marked "repeatable" replace the entire YAML list as soon as they are given once. A single
  empty value (--exclude-image-contains=) clears the list; an empty value together with other
  values is an error. Commas are ordinary characters: one flag carries exactly one value.

  A YAML file must contain config_version: 1 (there is no flag for it). Unknown keys, duplicate
  keys, wrong types, invalid values, empty list entries and multiple documents are rejected.
  Values are never guessed: blank values are errors (write [] for an empty list and "" for an
  empty string), durations need a unit (5s), and numbers or yes/no are not strings or booleans.

Configuration file search (at most one file is loaded, files are never merged):
  1. --config PATH        must exist and be readable
  2. ./process-watcher.yaml in the working directory
  3. process-watcher.yaml next to the real binary (symlinks are resolved)
  4. the built-in defaults, if none of the above exists
  A file that exists but is unreadable or invalid is an error; it is never skipped.
  Relative file paths (--log-file, --tcp-ca-file), also when they come from YAML, are resolved
  against the working directory of the invocation.

Units:
  Sizes ending in _mb (--log-rotate-size-mb, --ring-buffer-mb) are MiB: 1 048 576 bytes.
  Durations use Go syntax such as 500ms, 5s or 1m30s. All sizes and durations must be positive,
  except --watch-max-depth and --max-retries, which may be 0.

Image matching:
  --watch-image-contains matches the file name of the program that is really executed (nginx,
  bash, curl), not argv[0] and not the full path. "nginx" also matches nginx-debug, but not a
  python process whose argument merely contains nginx. For a script the image is its interpreter:
  ./deploy.sh runs as bash (or whatever its shebang names), so watch for bash; the script name
  only shows up in the arguments (see --capture-argv). Matching is case-sensitive unless
  --watch-ignore-case is set. Exclusions only filter the reports; they never stop the tracking of
  a process or of its descendants.
`

const usageKillNote = `
  Note on kill rules: they apply only to confirmed descendants of observed roots, never to the
  root itself, PID 1 or this agent. A hit sends SIGKILL to that single process instance. This is
  a reaction after detection, not preventive blocking: a short-lived process may be finished
  before the agent reacts and side effects of the program are not prevented. check-config and
  print-config never send signals. Strings and regular expressions are ORed over all selected
  fields. Strings are literal and case-sensitive, independent of --watch-ignore-case. Regular
  expressions use Go (RE2) syntax and are unanchored: use ^ and $ for the whole value and (?i) to
  ignore case. The fields are image (the executed file name, the default), image_path (the full
  path) and argv (every argument separately, including argv[0]); argv requires
  --capture-argv=true, which is never enabled implicitly. Missing or truncated values never
  match. --kill-dry-run writes the audit events without sending a signal.
`

const usageTail = `
Exit codes:
  0  success, including a clean stop after SIGINT or SIGTERM
  1  runtime error
  2  configuration or usage error
  3  unsupported platform or missing collector prerequisites

Examples:
  # Local observation only
  sudo ./process-watcher --watch-image-contains nginx --log-file /var/log/process-watcher/events.jsonl

  # Local log plus TCP, UDP and webhook, ignoring one helper in the remote outputs
  sudo ./process-watcher --watch-image-contains nginx --exclude-image-contains legitimate-helper --log-file /var/log/process-watcher/events.jsonl --tcp-address collector.example.net:9000 --udp-address 192.0.2.20:9001 --webhook-url https://collector.example.net/hooks/processes

  # Kill rules: terminate matching descendants of nginx (needs --capture-argv=true for argv)
  sudo ./process-watcher --watch-image-contains nginx --capture-argv=true --kill-enabled=true --kill-field image --kill-field argv --kill-string demo-long-running-helper --kill-regex '^(useradd|usermod)$'
`

// Usage returns the complete --help text.
func Usage() string {
	var b strings.Builder
	b.WriteString(usageIntro)

	b.WriteString("\nGeneral flags:\n")
	writeFlag(&b, "--config PATH", "YAML configuration file; see the search order above.", "")
	writeFlag(&b, "-h, --help", "Show this help and exit.", "")
	writeFlag(&b, "--version", "Show the version and exit.", "")

	section := ""
	for _, spec := range flagSpecs {
		if spec.Section != section {
			section = spec.Section
			b.WriteString("\n" + section + " flags:\n")
		}
		display := "--" + spec.Name
		if spec.Arg == "" {
			display += "[=BOOL]"
		} else {
			display += " " + spec.Arg
		}
		info := "YAML key: " + spec.Key + "; default: " + defaultText(spec.Key)
		if k, _ := kindOf(leafType(spec.Key)); k == kindList {
			info += "; repeatable"
		}
		writeFlag(&b, display, spec.Help, info)
		if spec.Section == secKill && spec.Name == "kill-regex" {
			b.WriteString(usageKillNote)
		}
	}
	b.WriteString(usageTail)
	return b.String()
}

// writeFlag prints a flag on its own line followed by the wrapped description
// and an optional line with its YAML key and default.
func writeFlag(b *strings.Builder, display, help, info string) {
	b.WriteString("  " + display + "\n")
	for _, line := range wrap(help, 88-8) {
		b.WriteString("        " + line + "\n")
	}
	if info != "" {
		b.WriteString("        " + info + "\n")
	}
}

// defaultText describes the built-in default of a YAML key.
func defaultText(key string) string {
	def := Default()
	v := leafMap(&def)[key]
	switch k, _ := kindOf(v.Type()); k {
	case kindList:
		if v.Len() == 0 {
			if key == "watch.image_contains" {
				return "none, required"
			}
			return "none"
		}
		items := make([]string, v.Len())
		for i := range items {
			items[i] = v.Index(i).String()
		}
		return strings.Join(items, ", ")
	case kindString:
		if v.String() == "" {
			return "empty"
		}
		return v.String()
	}
	return scalarText(key, v)
}

// wrap breaks text into lines of at most width characters at spaces.
func wrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
