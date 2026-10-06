#!/usr/bin/env python3
"""Run Suricata in unix-socket mode and send it commands read from stdin.

Usage: sc-driver.py SURICATA [ARGS...] < commands

Each command must be answered within SC_TIMEOUT seconds (default 30). If
Suricata stops answering, for example because it deadlocked, it is killed and
the driver exits non-zero. The test then fails instead of hanging the run.
Replies are written to $OUTPUT_DIR/sc.json.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

TIMEOUT = float(os.environ.get("SC_TIMEOUT", "30"))


def command_json(line):
    parts = line.split()
    cmd = {"command": parts[0]}
    if parts[0] in ("register-tenant", "reload-tenant"):
        cmd["arguments"] = {"id": int(parts[1])}
        if len(parts) > 2:
            cmd["arguments"]["filename"] = parts[2]
    elif parts[0] == "unregister-tenant":
        cmd["arguments"] = {"id": int(parts[1])}
    return cmd


def request(sock, msg):
    sock.sendall((json.dumps(msg) + "\n").encode())
    buf = b""
    while True:
        data = sock.recv(65536)
        if not data:
            raise ConnectionError("socket closed by Suricata")
        buf += data
        try:
            return json.loads(buf)
        except ValueError:
            continue


def connect(path, proc):
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("Suricata exited during startup")
        if os.path.exists(path):
            sock = socket.socket(socket.AF_UNIX)
            try:
                sock.connect(path)
                return sock
            except OSError:
                sock.close()
        time.sleep(0.1)
    raise TimeoutError("unix socket not ready")


def main():
    # Keep the socket path short: AF_UNIX paths are limited to ~104 bytes.
    sockdir = tempfile.mkdtemp(prefix="sv-sc-")
    path = os.path.join(sockdir, "socket")
    proc = subprocess.Popen(sys.argv[1:] + ["--unix-socket=" + path])
    failed = False
    try:
        sock = connect(path, proc)
        sock.settimeout(TIMEOUT)
        request(sock, {"version": "0.2"})
        with open(os.path.join(os.environ.get("OUTPUT_DIR", "."), "sc.json"), "w") as out:
            for line in sys.stdin:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    reply = request(sock, command_json(line))
                except socket.timeout:
                    print("error: no reply to '%s' after %ds; Suricata is hung" % (line, TIMEOUT),
                          file=sys.stderr)
                    return 2
                out.write(json.dumps(reply) + "\n")
                if reply.get("return") != "OK":
                    print("error: '%s' failed: %s" % (line, reply.get("message")), file=sys.stderr)
                    failed = True
                    break
            try:
                request(sock, {"command": "shutdown"})
            except socket.timeout:
                print("error: no reply to 'shutdown'; Suricata is hung", file=sys.stderr)
                return 2
        proc.wait(timeout=TIMEOUT)
        if proc.returncode != 0:
            print("error: Suricata exited with %d" % proc.returncode, file=sys.stderr)
            return 1
        return 1 if failed else 0
    except Exception as err:
        print("error: %s" % err, file=sys.stderr)
        return 2
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        shutil.rmtree(sockdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
