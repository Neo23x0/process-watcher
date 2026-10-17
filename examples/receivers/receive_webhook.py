#!/usr/bin/env python3
"""Minimal receiver for the process-watcher webhook: POST with one JSONL line.

    python3 receive_webhook.py 127.0.0.1 8080

The request carries X-Event-ID (the event_id) and, when token_env is set,
"Authorization: Bearer <token>". Any 2xx answer counts as accepted; 408, 429
and 5xx are retried by the agent with the same body.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        ev = json.loads(body)
        print(self.headers.get("X-Event-ID"), ev["sequence"], ev["event_type"], flush=True)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    host, port = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) == 3 else ("127.0.0.1", 8080)
    HTTPServer((host, port), Handler).serve_forever()
