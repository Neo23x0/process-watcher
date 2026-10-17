// Package output delivers already serialized JSONL events to the mandatory
// local log file and to the optional remote transports (TCP, UDP, HTTP
// webhook).
//
// An event is one UTF-8 JSON object terminated by a single '\n'. The caller
// serializes it once; the same []byte is handed to every output and must not
// be modified afterwards, so all outputs carry byte-identical data.
//
// The local file is synchronous: File.Write returns every error to the caller,
// who is expected to abort. Remote outputs are asynchronous and best effort:
// each has a bounded queue and exactly one worker goroutine, so a slow or dead
// target can neither block callers nor other outputs. DELIVERY.md describes
// the guarantees and their limits.
//
// The package imports no other project package and is configured through the
// plain option structs defined here.
package output
