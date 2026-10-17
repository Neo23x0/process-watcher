package config

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeEnv is an in-memory Env that counts file system accesses.
type fakeEnv struct {
	cwd     string
	exe     string
	exeErr  error
	files   map[string]string // absolute path -> content
	dirs    map[string]bool
	links   map[string]string // EvalSymlinks: path -> target
	vars    map[string]string
	readErr map[string]error
	statErr map[string]error
	stats   map[string]int
	reads   map[string]int
	envKeys []string // variables that were read
}

func newFakeEnv() *fakeEnv {
	return &fakeEnv{
		cwd:     "/work",
		exe:     "/opt/pw/process-watcher",
		files:   map[string]string{},
		dirs:    map[string]bool{},
		links:   map[string]string{},
		vars:    map[string]string{},
		readErr: map[string]error{},
		statErr: map[string]error{},
		stats:   map[string]int{},
		reads:   map[string]int{},
	}
}

type fakeInfo struct {
	name string
	size int64
	mode fs.FileMode
}

func (i fakeInfo) Name() string       { return i.name }
func (i fakeInfo) Size() int64        { return i.size }
func (i fakeInfo) Mode() fs.FileMode  { return i.mode }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return i.mode.IsDir() }
func (i fakeInfo) Sys() any           { return nil }

func (f *fakeEnv) Env() Env {
	return Env{
		Getenv: func(k string) string {
			f.envKeys = append(f.envKeys, k)
			return f.vars[k]
		},
		Getwd:      func() (string, error) { return f.cwd, nil },
		Executable: func() (string, error) { return f.exe, f.exeErr },
		Stat: func(name string) (fs.FileInfo, error) {
			f.stats[name]++
			if err := f.statErr[name]; err != nil {
				return nil, err
			}
			if f.dirs[name] {
				return fakeInfo{name: filepath.Base(name), mode: fs.ModeDir | 0o755}, nil
			}
			if c, ok := f.files[name]; ok {
				return fakeInfo{name: filepath.Base(name), size: int64(len(c)), mode: 0o644}, nil
			}
			return nil, &fs.PathError{Op: "stat", Path: name, Err: syscall.ENOENT}
		},
		ReadFile: func(name string) ([]byte, error) {
			f.reads[name]++
			if err := f.readErr[name]; err != nil {
				return nil, err
			}
			c, ok := f.files[name]
			if !ok {
				return nil, &fs.PathError{Op: "open", Path: name, Err: syscall.ENOENT}
			}
			return []byte(c), nil
		},
		EvalSymlinks: func(p string) (string, error) {
			if t, ok := f.links[p]; ok {
				return t, nil
			}
			return p, nil
		},
	}
}

// file registers a file at an absolute path.
func (f *fakeEnv) file(path, content string) *fakeEnv {
	f.files[path] = content
	return f
}

// cwdFile registers the default configuration file in the working directory.
func (f *fakeEnv) cwdFile(content string) *fakeEnv {
	return f.file(filepath.Join(f.cwd, DefaultFileName), content)
}

// withWatch prepends a watch pattern so that run-style validation passes.
func withWatch(args ...string) []string {
	return append([]string{"--watch-image-contains", "nginx"}, args...)
}

func mustResolve(t *testing.T, env *fakeEnv, args ...string) *Resolved {
	t.Helper()
	r, err := Resolve(args, env.Env())
	if err != nil {
		t.Fatalf("Resolve(%q) failed: %v", args, err)
	}
	return r
}

// resolveErrors expects Resolve to fail with configuration errors only.
func resolveErrors(t *testing.T, env *fakeEnv, args ...string) []*Error {
	t.Helper()
	r, err := Resolve(args, env.Env())
	if err == nil {
		t.Fatalf("Resolve(%q) succeeded, want an error (config: %+v)", args, r.Config)
	}
	if r != nil {
		t.Errorf("Resolve returned a non-nil result together with an error")
	}
	errs := flatten(err)
	if len(errs) == 0 {
		t.Fatalf("Resolve(%q) returned %T %v, want *Error values", args, err, err)
	}
	return errs
}

// flatten returns all *Error values of a possibly joined error.
func flatten(err error) []*Error {
	if err == nil {
		return nil
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		var out []*Error
		for _, e := range j.Unwrap() {
			out = append(out, flatten(e)...)
		}
		return out
	}
	var ce *Error
	if errors.As(err, &ce) {
		return []*Error{ce}
	}
	return nil
}

func paths(errs []*Error) []string {
	out := make([]string, len(errs))
	for i, e := range errs {
		out[i] = e.Path
	}
	return out
}

// wantOneError asserts that errs holds exactly one error with the given path
// whose text contains all fragments.
func wantOneError(t *testing.T, errs []*Error, path string, fragments ...string) *Error {
	t.Helper()
	if len(errs) != 1 {
		t.Fatalf("got %d errors %v, want exactly one for %q", len(errs), errs, path)
	}
	e := errs[0]
	if e.Path != path {
		t.Errorf("error path = %q, want %q (error: %v)", e.Path, path, e)
	}
	for _, f := range fragments {
		if !strings.Contains(e.Error(), f) {
			t.Errorf("error %q does not contain %q", e.Error(), f)
		}
	}
	return e
}
