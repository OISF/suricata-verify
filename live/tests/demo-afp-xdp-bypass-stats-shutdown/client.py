#!/usr/bin/env python3
"""Client driver for the live bypass test.

Open one TCP connection and send a fixed TLS-like payload 97 times.
"""

import socket
import sys
import time

HOST = "10.200.0.1"
PORT = 7000

PAYLOAD = b"\x17\x03\x03" + b"\x00" * 100
COUNT = 97


def main():
    try:
        with socket.create_connection((HOST, PORT), timeout=10) as s:
            s.settimeout(10)
            for _ in range(COUNT):
                s.sendall(PAYLOAD)
                time.sleep(0.01)
    except Exception as err:  # noqa: BLE001 - surface any failure to the runner
        print(f"ERROR: {err}", file=sys.stderr, flush=True)
        return 1
    print(f"client OK: sent {len(PAYLOAD) * COUNT} bytes", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
