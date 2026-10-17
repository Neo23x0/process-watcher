// Package schemacheck validates event lines against the JSON Schema of the
// event contract. It is used by tests only; the agent itself does not link it.
package schemacheck

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Neo23x0/process-watcher/schema"
)

var (
	once     sync.Once
	compiled *jsonschema.Schema
	initErr  error
)

func compile() (*jsonschema.Schema, error) {
	once.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema.EventSchema))
		if err != nil {
			initErr = fmt.Errorf("parse schema: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource("event.schema.json", doc); err != nil {
			initErr = err
			return
		}
		compiled, initErr = c.Compile("event.schema.json")
	})
	return compiled, initErr
}

// Validate checks one JSONL line (with or without the trailing newline).
func Validate(line []byte) error {
	sch, err := compile()
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(bytes.TrimRight(line, "\n")))
	if err != nil {
		return fmt.Errorf("not JSON: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("%v", err)
	}
	return nil
}
