#!/usr/bin/env python3
"""Minimal receiver for the process-watcher UDP output: one event per datagram.

    python3 receive_udp.py 0.0.0.0 9001
"""
import json
import socket
import sys

host, port = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) == 3 else ("127.0.0.1", 9001)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((host, port))
while True:
    data, _ = sock.recvfrom(65535)
    ev = json.loads(data)
    print(ev["sequence"], ev["event_type"], flush=True)
