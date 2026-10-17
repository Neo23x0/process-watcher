#!/usr/bin/env python3
"""Minimal receiver for the process-watcher TCP output (newline delimited JSON).

    python3 receive_tcp.py 0.0.0.0 9000

TCP gives no acknowledgement: after a reconnect the agent may send an event
again (same event_id), so deduplicate on event_id if you need that.
"""
import json
import socketserver
import sys


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        for raw in self.rfile:  # the byte stream is split into lines here
            try:
                ev = json.loads(raw)
            except ValueError:
                continue  # an unterminated fragment of an interrupted connection
            print(ev["sequence"], ev["event_type"], ev.get("process", {}) and ev["process"].get("image"), flush=True)


if __name__ == "__main__":
    host, port = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) == 3 else ("127.0.0.1", 9000)
    with socketserver.ThreadingTCPServer((host, port), Handler) as srv:
        srv.daemon_threads = True
        srv.serve_forever()
