package event

import (
	"time"

	"github.com/Neo23x0/process-watcher/internal/clock"
)

// Factory creates events with the fields every event shares. The sequence
// number is assigned by the sink at emission time so that it increases in
// output order across all producers.
type Factory struct {
	AgentInstanceID string
	Host            Host
	Clock           clock.Clock
	// NewID generates event ids; NewUUID when nil. Tests inject a counter.
	NewID func() string
}

// New creates an agent event stamped with the current time.
func (f *Factory) New(typ, source string) *Event {
	now := f.Clock.Now().UTC()
	return f.build(typ, source, now, nil)
}

// NewAt creates an event whose timestamp is the given kernel time
// (CLOCK_BOOTTIME nanoseconds) converted to UTC.
func (f *Factory) NewAt(typ, source string, bootNS uint64) *Event {
	return f.build(typ, source, clock.ToWall(f.Clock, bootNS), StrNS(bootNS))
}

func (f *Factory) build(typ, source string, ts time.Time, bootNS *string) *Event {
	return &Event{
		SchemaVersion:   SchemaVersion,
		EventID:         f.id(),
		AgentInstanceID: f.AgentInstanceID,
		EventType:       typ,
		Timestamp:       Time(ts),
		ObservedAt:      Time(f.Clock.Now().UTC()),
		BootTimeNS:      bootNS,
		Host:            f.Host,
		Source:          source,
		Filter:          Filter{Matches: []FilterMatch{}, SuppressedOutputs: []string{}},
		DataQuality: DataQuality{
			MissingFields:   []Missing{},
			TruncatedFields: []string{},
			SanitizedFields: []string{},
		},
	}
}

func (f *Factory) id() string {
	if f.NewID != nil {
		return f.NewID()
	}
	return NewUUID()
}
