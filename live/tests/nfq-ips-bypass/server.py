#!/usr/bin/env python3
"""Tiny TCP echo + byte-counting server for the live bypass test.

For every connection it echoes back every byte it receives and counts the
total. When a connection closes it appends a JSON line describing how many
bytes that connection delivered to ``$OUT`` (argv[1]). The client uses the
echo to prove that every byte it sent survived the trip through Suricata
(i.e. that bypassing the flow did not break end-to-end delivery), and the
JSON file lets a check assert the server actually received the full payload.
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
            # Echo everything straight back.
            sock.sendall(data)
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
