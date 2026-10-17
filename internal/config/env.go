package config

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// maxFileBytes bounds the size of a configuration file.
const maxFileBytes = 1 << 20

// Env injects everything Resolve reads from the process environment so that
// tests need no real file system. The zero value of a field means "not
// available": a nil Getenv is an empty environment, nil Stat and ReadFile see
// no files, a nil Executable disables the search next to the binary, a nil
// EvalSymlinks is the identity and a nil Getwd makes Resolve fail.
type Env struct {
	// Getenv is only used to read the variable named by
	// outputs.webhook.token_env; the environment is no configuration layer.
	Getenv func(key string) string
	// Getwd returns the working directory of the invocation. Relative file
	// paths are resolved against it.
	Getwd func() (string, error)
	// Executable returns the path of the running binary (os.Executable).
	Executable func() (string, error)
	// ReadFile reads a whole configuration file.
	ReadFile func(name string) ([]byte, error)
	// Stat follows symlinks, like os.Stat.
	Stat func(name string) (fs.FileInfo, error)
	// EvalSymlinks resolves symlinks in a path, like filepath.EvalSymlinks.
	EvalSymlinks func(path string) (string, error)
}

// OSEnv returns the Env backed by the operating system.
func OSEnv() Env {
	return Env{
		Getenv:       os.Getenv,
		Getwd:        os.Getwd,
		Executable:   os.Executable,
		ReadFile:     readFileLimited,
		Stat:         os.Stat,
		EvalSymlinks: filepath.EvalSymlinks,
	}
}

// readFileLimited is os.ReadFile with a size limit, so that pointing --config
// at an endless file cannot exhaust memory.
func readFileLimited(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("file is larger than %d bytes", maxFileBytes)
	}
	return data, nil
}

func (e Env) stat(name string) (fs.FileInfo, error) {
	if e.Stat == nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
	}
	return e.Stat(name)
}

func (e Env) readFile(name string) ([]byte, error) {
	if e.ReadFile == nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return e.ReadFile(name)
}

func (e Env) evalSymlinks(path string) (string, error) {
	if e.EvalSymlinks == nil {
		return path, nil
	}
	return e.EvalSymlinks(path)
}
