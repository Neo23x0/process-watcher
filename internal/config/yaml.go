package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// loadYAML strictly decodes one YAML document over base.
//
// The document is first parsed into a node tree and checked against the
// schema of Config. This reports unknown and duplicate keys, wrong types and
// the leniencies of the YAML decoder (nulls, floats for integers, yes/no for
// booleans, numbers for strings) with the configuration path and line of the
// offending value, and yields the line of every value for later diagnostics.
// Only then the document is decoded with KnownFields(true).
func loadYAML(file string, data []byte, base Config) (Config, map[string]origin, []*Error) {
	c := &yamlChecker{file: file, origins: make(map[string]origin)}
	root := c.parse(data)
	if root == nil {
		return base, nil, c.errs
	}
	c.structNode(root, reflect.TypeFor[Config](), "", true)
	if len(c.errs) > 0 {
		return base, nil, c.errs
	}

	cfg := base
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		c.decodeError(err)
		return base, nil, c.errs
	}
	return cfg, c.origins, nil
}

type yamlChecker struct {
	file    string
	errs    []*Error
	origins map[string]origin
}

func (c *yamlChecker) errAt(line int, path, format string, args ...any) {
	c.errs = append(c.errs, &Error{Path: path, Msg: fmt.Sprintf(format, args...), File: c.file, Line: line})
}

// parse returns the root node of the single document in data, or nil after
// recording an error for an empty file, a syntax error or several documents.
func (c *yamlChecker) parse(data []byte) *yaml.Node {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			c.errAt(0, "", "the file is empty; config_version is required")
		} else {
			c.syntaxError(err)
		}
		return nil
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		c.errAt(extra.Line, "", "multiple YAML documents are not supported; use a single document")
		return nil
	case !errors.Is(err, io.EOF):
		c.syntaxError(err)
		return nil
	}
	if len(doc.Content) == 0 {
		c.errAt(doc.Line, "", "the file is empty; config_version is required")
		return nil
	}
	root := doc.Content[0]
	if root.Kind == yaml.ScalarNode && root.ShortTag() == "!!null" {
		c.errAt(root.Line, "", "the file contains no settings; config_version is required")
		return nil
	}
	return root
}

var (
	yamlPrefixRe = regexp.MustCompile(`^yaml: (?:line (\d+): )?`)
	yamlLineRe   = regexp.MustCompile(`^line (\d+): `)
)

func (c *yamlChecker) syntaxError(err error) {
	msg, line := err.Error(), 0
	if m := yamlPrefixRe.FindStringSubmatch(msg); m != nil {
		line, _ = strconv.Atoi(m[1])
		msg = msg[len(m[0]):]
	}
	c.errAt(line, "", "invalid YAML: %s", msg)
}

// decodeError reports a failure of the final decode. The schema check should
// make this unreachable; it stays as a safety net.
func (c *yamlChecker) decodeError(err error) {
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		c.syntaxError(err)
		return
	}
	for _, msg := range te.Errors {
		line := 0
		if m := yamlLineRe.FindStringSubmatch(msg); m != nil {
			line, _ = strconv.Atoi(m[1])
			msg = msg[len(m[0]):]
		}
		c.errAt(line, "", "invalid configuration: %s", msg)
	}
}

// structNode checks a mapping against the struct type t.
func (c *yamlChecker) structNode(n *yaml.Node, t reflect.Type, path string, top bool) {
	if n.Kind != yaml.MappingNode {
		c.errAt(n.Line, path, "must be a mapping of settings, got %s", describe(n))
		return
	}
	var keys []string
	types := make(map[string]reflect.Type)
	for i := range t.NumField() {
		if key := yamlKey(t.Field(i)); key != "-" {
			keys = append(keys, key)
			types[key] = t.Field(i).Type
		}
	}

	seen := make(map[string]*yaml.Node, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			c.errAt(k.Line, path, "mapping keys must be plain strings, got %s", describe(k))
			continue
		}
		kpath := joinKey(path, k.Value)
		if k.ShortTag() == "!!merge" {
			c.errAt(k.Line, path, "YAML merge keys (<<) are not supported")
			continue
		}
		if first, dup := seen[k.Value]; dup {
			c.errAt(k.Line, kpath, "duplicate key (first defined on line %d)", first.Line)
			continue
		}
		seen[k.Value] = k
		ft, ok := types[k.Value]
		if !ok {
			c.errAt(k.Line, kpath, "unknown key (valid keys: %s)", strings.Join(keys, ", "))
			continue
		}
		c.value(v, ft, kpath)
		if top && k.Value == "config_version" {
			c.checkVersion(v, kpath)
		}
	}
	if top && seen["config_version"] == nil {
		c.errAt(n.Line, "config_version", "is required; the only supported value is %d", CurrentVersion)
	}
}

func (c *yamlChecker) checkVersion(n *yaml.Node, path string) {
	var v int
	if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!int" && n.Decode(&v) == nil && v != CurrentVersion {
		c.errAt(n.Line, path, "unsupported version %d (this program supports version %d)", v, CurrentVersion)
	}
}

// value checks the node of one field of type t.
func (c *yamlChecker) value(n *yaml.Node, t reflect.Type, path string) {
	if n.Kind == yaml.AliasNode {
		c.errAt(n.Line, path, "YAML aliases are not supported")
		return
	}
	if t.Kind() == reflect.Struct {
		c.structNode(n, t, path, false)
		return
	}
	k, ok := kindOf(t)
	if !ok {
		panic(fmt.Sprintf("config: unsupported type %v at %s", t, path))
	}
	if k == kindList {
		c.list(n, path)
		return
	}
	c.scalar(n, k, path)
}

func (c *yamlChecker) scalar(n *yaml.Node, k kind, path string) {
	var want, desc string
	switch k {
	case kindBool:
		want, desc = "!!bool", "a boolean (true or false)"
	case kindInt:
		want, desc = "!!int", "an integer"
	case kindDuration:
		want, desc = "!!str", "a duration string such as 500ms, 5s or 1m30s"
	default:
		want, desc = "!!str", "a string"
	}
	if n.Kind != yaml.ScalarNode || n.ShortTag() != want {
		c.errAt(n.Line, path, "must be %s, got %s%s", desc, describe(n), scalarHint(n, k))
		return
	}
	switch k {
	case kindInt:
		var v int
		if err := n.Decode(&v); err != nil {
			c.errAt(n.Line, path, "integer is out of range")
			return
		}
	case kindDuration:
		if _, err := time.ParseDuration(n.Value); err != nil {
			c.errAt(n.Line, path, "invalid duration %q (use Go syntax such as 500ms, 5s or 1m30s)", n.Value)
			return
		}
	}
	c.origins[path] = origin{file: c.file, line: n.Line}
}

// scalarHint helps with the typical mistakes of leaf values.
func scalarHint(n *yaml.Node, k kind) string {
	if n.Kind != yaml.ScalarNode {
		return ""
	}
	switch tag := n.ShortTag(); {
	case tag == "!!null" && k == kindString:
		return `; write "" for an empty string`
	case k == kindString && (tag == "!!int" || tag == "!!float" || tag == "!!bool"):
		return "; put quotes around the value to make it a string"
	case k == kindDuration && (tag == "!!int" || tag == "!!float"):
		return "; a bare number has no unit"
	}
	return ""
}

func (c *yamlChecker) list(n *yaml.Node, path string) {
	if n.Kind != yaml.SequenceNode {
		hint := ""
		if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null" {
			hint = "; write [] for an empty list"
		}
		c.errAt(n.Line, path, "must be a list, got %s%s", describe(n), hint)
		return
	}
	for i, e := range n.Content {
		p := fmt.Sprintf("%s[%d]", path, i)
		switch {
		case e.Kind == yaml.AliasNode:
			c.errAt(e.Line, p, "YAML aliases are not supported")
		case e.Kind == yaml.ScalarNode && e.ShortTag() == "!!null":
			c.errAt(e.Line, p, "must not be empty")
		case e.Kind != yaml.ScalarNode || e.ShortTag() != "!!str":
			c.errAt(e.Line, p, "must be a string, got %s%s", describe(e), scalarHint(e, kindString))
		default:
			c.origins[p] = origin{file: c.file, line: e.Line}
		}
	}
	c.origins[path] = origin{file: c.file, line: n.Line}
}

// describe names the type of a node for error messages without echoing its
// value, which may be a secret.
func describe(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a list"
	case yaml.AliasNode:
		return "an alias"
	case yaml.ScalarNode:
		switch tag := n.ShortTag(); tag {
		case "!!str":
			return "a string"
		case "!!int":
			return "an integer"
		case "!!float":
			return "a number"
		case "!!bool":
			return "a boolean"
		case "!!null":
			return "an empty value"
		case "!!timestamp":
			return "a timestamp"
		case "!!binary":
			return "binary data"
		default:
			return "a value with the tag " + tag
		}
	}
	return "an unsupported node"
}
