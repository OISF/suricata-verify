#!/usr/bin/env python3
"""Client driver for the live bypass test.

Two real TCP connections through Suricata:

1. The *bypass* flow: start a flow with our bypass marker, then a story then
   the tripwire text. This flow should now alert on the tripwire text and the
   flow should be marked as bypassed.

2. The *control* flow: just send our story followed by the tripwire text. As no
   bypass was done, we should alert on the tripwire text.

In both cases the client always checks that what was sent was echo'd back.

The script exits non-zero if any byte fails to round-trip, which the runner
treats as a test failure.
"""

import socket
import sys
import time

HOST = "10.200.0.1"
PORT = 7000


STORY = b"""
Marty the meerkat stood on the warm desert sand every morning, stretching as tall as his little legs allowed so he could watch over his family. One day, while everyone else searched for breakfast, Marty spotted a shiny blue beetle struggling on its back beside a cactus. He hurried over, flipped it gently upright, and the beetle buzzed in happy circles before flying away. Later that afternoon, when a hungry eagle swept low across the dunes, a flash of blue wings darted in front of Marty and startled the eagle just long enough for him to squeak a warning. His family dove safely into their burrow, and from that day on, Marty learned that even the smallest kindness could come back in the biggest way.
"""


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"connection closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def send_and_verify_echo(sock, payload, what):
    sock.sendall(payload)
    echo = recv_exact(sock, len(payload))
    if echo != payload:
        raise AssertionError(f"{what}: echo mismatch ({len(echo)}/{len(payload)} bytes)")
    print(f"{what}: {len(payload)} bytes echoed back OK", flush=True)


def bypass_flow():
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.settimeout(10)

        # First send that should trigger the bypass.
        send_and_verify_echo(s, b"BYPASS", "bypass-flow trigger")

        # Wait a moment for the bypass to be applied.
        time.sleep(1.0)

        # Now send the story.
        send_and_verify_echo(s, STORY, "bypass-flow payload")

        # Now send the tripwire.
        send_and_verify_echo(s, b"TRIPWIRE", "bypass-flow-payload")

def control_flow():
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.settimeout(10)
        send_and_verify_echo(s, STORY, "control-flow payload")
        send_and_verify_echo(s, b"TRIPWIRE", "control-flow-payload")


def main():
    try:
        bypass_flow()
        control_flow()
    except Exception as err:  # noqa: BLE001 - surface any failure to the runner
        print(f"ERROR: {err}", file=sys.stderr, flush=True)
        return 1
    print("client OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
