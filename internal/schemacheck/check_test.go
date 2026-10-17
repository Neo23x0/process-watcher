package schemacheck

import (
	"strings"
	"testing"
)

// A minimal valid agent.health-free example: agent.ready.
const readyLine = `{"schema_version":1,"event_id":"72c89dca-44f1-4224-9ab6-9cb77081a756","agent_instance_id":"8f733e92-0ef0-4a3b-829c-0c90e056bdf6","sequence":2,"event_type":"agent.ready","timestamp":"2026-10-17T12:00:00.123456789Z","observed_at":"2026-10-17T12:00:00.124000000Z","boot_time_ns":null,"host":{"hostname":"web01","boot_id":"b53c175a-2d90-4d0c-8c94-dfc2c15eb199"},"source":"agent","process":null,"parent":null,"root":null,"lineage":null,"filter":{"excluded":false,"matches":[],"suppressed_outputs":[]},"data_quality":{"missing_fields":[],"truncated_fields":[],"sanitized_fields":[],"collection_gap":false},"details":{"observing_since_boot_ns":"1","snapshot_start_boot_ns":"2","snapshot_end_boot_ns":"3","snapshot_processes":4,"discovered_roots":0,"discovered_descendants":0,"buffered_records":0,"note":"n"}}`

func TestAValidEventPasses(t *testing.T) {
	if err := Validate([]byte(readyLine + "\n")); err != nil {
		t.Fatal(err)
	}
}

// The schema must reject real violations, otherwise validating every event of
// every test would prove nothing.
func TestViolationsAreRejected(t *testing.T) {
	for name, mutate := range map[string]func(string) string{
		"wrong version":       func(s string) string { return strings.Replace(s, `"schema_version":1`, `"schema_version":2`, 1) },
		"event id not a uuid": func(s string) string { return strings.Replace(s, "72c89dca-44f1-4224-9ab6-9cb77081a756", "nope", 1) },
		"timestamp w/o nanos": func(s string) string { return strings.Replace(s, ".123456789Z", "Z", 1) },
		"unknown event type":  func(s string) string { return strings.Replace(s, `"agent.ready"`, `"agent.what"`, 1) },
		"unknown top level key": func(s string) string {
			return strings.Replace(s, `"source":"agent",`, `"source":"agent","extra":1,`, 1)
		},
		"agent event with ebpf": func(s string) string { return strings.Replace(s, `"source":"agent"`, `"source":"ebpf"`, 1) },
		"boot time on agent":    func(s string) string { return strings.Replace(s, `"boot_time_ns":null`, `"boot_time_ns":"5"`, 1) },
		"ns as number": func(s string) string {
			return strings.Replace(s, `"observing_since_boot_ns":"1"`, `"observing_since_boot_ns":1`, 1)
		},
		"details key missing":    func(s string) string { return strings.Replace(s, `"buffered_records":0,`, ``, 1) },
		"details extra key":      func(s string) string { return strings.Replace(s, `"note":"n"`, `"note":"n","x":1`, 1) },
		"collection_gap missing": func(s string) string { return strings.Replace(s, `,"collection_gap":false`, ``, 1) },
		"sequence zero":          func(s string) string { return strings.Replace(s, `"sequence":2`, `"sequence":0`, 1) },
		"not json":               func(s string) string { return "{" },
	} {
		t.Run(name, func(t *testing.T) {
			if err := Validate([]byte(mutate(readyLine))); err == nil {
				t.Fatal("must be rejected")
			}
		})
	}
}

func TestProcessEventsNeedTheirParts(t *testing.T) {
	// A process.exec must carry process, root and lineage; an agent event must not.
	bad := strings.Replace(readyLine, `"event_type":"agent.ready"`, `"event_type":"process.exec"`, 1)
	if err := Validate([]byte(bad)); err == nil {
		t.Fatal("a process event without process/root/lineage must be rejected")
	}
}
