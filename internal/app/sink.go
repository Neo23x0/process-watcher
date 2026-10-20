// Package app wires the agent together: collector, process model, response
// worker, local log and remote outputs, plus the run loop with the startup
// reconciliation, health reporting and the orderly shutdown.
package app

import (
	"context"
	"log/slog"
	"sync"

	"github.com/Neo23x0/process-watcher/internal/config"
	"github.com/Neo23x0/process-watcher/internal/event"
	"github.com/Neo23x0/process-watcher/internal/output"
)

// logFile is the local log; *output.File implements it. The interface exists
// so tests can inject write failures.
type logFile interface {
	Write(line []byte) error
	Sync() error
	Close() error
	Stats() output.FileStats
	Repair() output.RepairInfo
}

// Sink is the single exit of all events. Under one lock it assigns the
// sequence number, applies the exclusion scope, serializes the event once,
// writes it to the local log and only then offers the same bytes to the remote
// queues, which never block. All producers (process model, response worker,
// health) share it, so the sequence increases in log order.
type Sink struct {
	mu      sync.Mutex
	file    logFile
	remotes []output.Remote
	scope   string

	seq           uint64
	fatal         error
	remotesClosed bool

	byType     map[string]uint64
	exclRemote uint64
	exclAll    uint64
	suppressed []string // names of the enabled remote outputs

	// log, when set before the first event, gets one console line per finished
	// kill decision. It is written outside the lock.
	log *slog.Logger
}

// NewSink creates the sink. scope is exclude.scope.
func NewSink(file logFile, remotes []output.Remote, scope string) *Sink {
	s := &Sink{file: file, remotes: remotes, scope: scope, byType: map[string]uint64{}}
	for _, r := range remotes {
		s.suppressed = append(s.suppressed, r.Name())
	}
	return s
}

// SetLog makes the sink print a console line for every finished kill decision.
// Call it before the first event.
func (s *Sink) SetLog(l *slog.Logger) { s.log = l }

// Emit implements proctree.Emitter and response.Emitter. A returned error is
// fatal: the local log is mandatory.
func (s *Sink) Emit(ev *event.Event) error {
	err := s.emit(ev)
	if err == nil && s.log != nil && ev.EventType == event.TypeKillResult {
		killDecisionNotice(s.log, ev)
	}
	return err
}

func (s *Sink) emit(ev *event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fatal != nil {
		return s.fatal
	}
	s.seq++
	ev.Sequence = s.seq

	toRemote := true
	if ev.Filter.Excluded {
		if s.scope == config.ScopeAll {
			s.exclAll++
			return nil // suppressed everywhere; the sequence gap and the counter show it
		}
		s.exclRemote++
		toRemote = false
		ev.Filter.SuppressedOutputs = append(ev.Filter.SuppressedOutputs, s.suppressed...)
	}
	line, err := ev.MarshalLine()
	if err != nil {
		s.fatal = err
		return err
	}
	if err := s.file.Write(line); err != nil {
		s.fatal = err
		return err
	}
	s.byType[ev.EventType]++
	if toRemote && !s.remotesClosed {
		for _, r := range s.remotes {
			r.Enqueue(ev.EventID, line)
		}
	}
	return nil
}

// Fatal returns the error that made the local log unusable, if any.
func (s *Sink) Fatal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fatal
}

// Counts returns the emitted events by type and the exclusion counters.
func (s *Sink) Counts() (byType map[string]uint64, exclRemote, exclAll uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byType = make(map[string]uint64, len(s.byType))
	for k, v := range s.byType {
		byType[k] = v
	}
	return byType, s.exclRemote, s.exclAll
}

// RemoteStats returns the delivery counters per remote output.
func (s *Sink) RemoteStats() map[string]output.RemoteStats {
	out := make(map[string]output.RemoteStats, len(s.remotes))
	for _, r := range s.remotes {
		out[r.Name()] = r.Stats()
	}
	return out
}

// CloseRemotes stops offering events to the remote outputs and shuts them
// down in parallel until ctx is done. It returns, per output, the number of
// accepted events that were not delivered.
func (s *Sink) CloseRemotes(ctx context.Context) map[string]int {
	s.mu.Lock()
	s.remotesClosed = true
	s.mu.Unlock()

	var wg sync.WaitGroup
	var mu sync.Mutex
	dropped := make(map[string]int, len(s.remotes))
	for _, r := range s.remotes {
		wg.Add(1)
		go func(r output.Remote) {
			defer wg.Done()
			n := r.Shutdown(ctx)
			mu.Lock()
			dropped[r.Name()] = n
			mu.Unlock()
		}(r)
	}
	wg.Wait()
	return dropped
}
