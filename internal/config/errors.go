package config

import (
	"errors"
	"fmt"
	"strings"
)

// Error describes one invalid configuration value or command line flag.
//
// Resolve may return several of them joined with errors.Join; use errors.As
// to extract one. Messages never contain secret values.
type Error struct {
	// Path is the configuration path including the list index, for example
	// "kill.regex[2]". For problems that exist only on the command line
	// (unparsable values, an empty value mixed into a list flag) it is the flag
	// name, for example "--log-rotate-size-mb". It is empty for problems of the
	// configuration file as a whole (syntax errors, empty file).
	Path string
	// Msg describes the problem without repeating Path.
	Msg string
	// File and Line locate the offending value in the YAML file, when known.
	File string
	Line int
	// Flag names the command line flag that supplied the offending value.
	Flag string
}

// Error formats as "file:line: path: message" for values from a YAML file and
// as "path: message (set by flag --name)" for values from the command line.
func (e *Error) Error() string {
	var b strings.Builder
	if e.File != "" {
		b.WriteString(e.File)
		if e.Line > 0 {
			fmt.Fprintf(&b, ":%d", e.Line)
		}
		b.WriteString(": ")
	}
	if e.Path != "" {
		b.WriteString(e.Path)
		b.WriteString(": ")
	}
	b.WriteString(e.Msg)
	if e.Flag != "" {
		fmt.Fprintf(&b, " (set by flag %s)", e.Flag)
	}
	return b.String()
}

// UsageError reports a malformed command line: an unknown flag or subcommand,
// a flag without its value or a stray positional argument. Like *Error it
// maps to exit code 2; callers usually add a hint to run with --help.
type UsageError struct {
	Msg string
}

func (e *UsageError) Error() string { return e.Msg }

func errorf(path, format string, args ...any) *Error {
	return &Error{Path: path, Msg: fmt.Sprintf(format, args...)}
}

// joinErrors returns nil, the single error or an errors.Join of all of them.
func joinErrors(errs []*Error) error {
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	}
	list := make([]error, len(errs))
	for i, e := range errs {
		list[i] = e
	}
	return errors.Join(list...)
}
