// Package schema embeds the JSON Schema of the JSONL event contract
// (schema_version 1) so that tests and tools can validate events against it.
package schema

import _ "embed"

// EventSchema is the JSON Schema (draft 2020-12) of one event line.
//
//go:embed event.schema.json
var EventSchema []byte
