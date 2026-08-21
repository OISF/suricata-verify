#!/usr/bin/env python3
"""Tiny TCP sink for the live bypass test.

For every connection, consume all bytes until the peer closes. When a
connection closes, append a JSON line with the byte count to ``$OUT``
(argv[1]) if provided.
"""

import json
import socket
import sys
import threading

HOST = "0.0.0.0"
PORT = 7000

out_path = sys.argv[1] if len(sys.argv) > 1 else None
out_lock = threading.Lock()
conn_no = 0


def record(conn_id, nbytes):
    if not out_path:
        return
    with out_lock:
        with open(out_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"conn": conn_id, "bytes": nbytes}) + "\n")


def handle(sock, conn_id):
    total = 0
    try:
        while True:
            data = sock.recv(65536)
            if not data:
                break
            total += len(data)
    finally:
        sock.close()
        record(conn_id, total)
        print(f"conn {conn_id}: received {total} bytes", flush=True)


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(16)
    print(f"listening on {HOST}:{PORT}", flush=True)
    global conn_no
    while True:
        client, _ = srv.accept()
        conn_no += 1
        t = threading.Thread(target=handle, args=(client, conn_no), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
