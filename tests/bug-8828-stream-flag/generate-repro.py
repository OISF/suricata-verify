#!/usr/bin/env python3
"""
Generate a pcap that reproduces the flag-wipe bug in
StreamTcp3whsStoreSynApplyToSsn() (stream-tcp.c).

Bug: when a queued/retransmitted SYN lacks the Window-Scale option,
the expression "ssn->flags &= STREAMTCP_FLAG_SERVER_WSCALE" instead of
"ssn->flags &= ~STREAMTCP_FLAG_SERVER_WSCALE" zeroes every flag bit
except SERVER_WSCALE (bit 4). This breaks 4WHS, TFO, ASYNC, and SACKOK.

This test verifies that after a SYN retransmit without WScale, the session
still properly accepts the completing SYN/ACK in a 4-way handshake.

Expected behavior (post-fix):
  - Packet #4 (SYN/ACK completing 4WHS) is accepted.
  - No "stream.3whs_synack_in_wrong_direction" event is logged.
  - Session reaches TCP_SYN_RECV (state 3).

With the bug:
  - PACKET #3 wipes ssn->flags to 0x10, destroying STREAMTCP_FLAG_4WHS.
  - Packet #4 is rejected with stream.3whs_synack_in_wrong_direction.
"""

from scapy.all import *

C = "10.0.0.1"    # client
S = "10.0.0.2"    # server
cp = 40000        # client port
sp = 80           # server port

pkts = [
    # ── Packet 1: client SYN with WScale + SACKOK ──────────────────
    # Sets up session, creates TcpSession, allocates stream state.
    # May set flags like STREAMTCP_FLAG_CLIENT_SACKOK, STREAMTCP_FLAG_TIMESTAMP
    Ether(src="00:00:00:00:01:01", dst="00:00:00:00:02:02") / \
    IP(src=C, dst=S) / \
    TCP(sport=cp, dport=sp, flags="S", seq=1000,
        options=[('MSS', 1460), ('WScale', 7), ('SAckOK', b'')]),

    # ── Packet 2: server bare SYN (simultaneous-open) ───────────────
    # Dispatched to StreamTcpPacketStateSynSent() -> TH_SYN branch.
    # PKT_IS_TOCLIENT path sets STREAMTCP_FLAG_4WHS at L2328.
    Ether(src="00:00:00:00:02:02", dst="00:00:00:00:01:01") / \
    IP(src=S, dst=C) / \
    TCP(sport=sp, dport=cp, flags="S", seq=2000,
        options=[('MSS', 1460)]),

    # ── Packet 3: client SYN retransmit, NO WScale option ───────────
    # Same 5-tuple and sequence as packet #1.
    # TcpStateQueueInitFromPktSyn leaves STREAMTCP_QUEUE_FLAG_WS clear
    # because TCP_HAS_WSCALE(p) is false.
    # StreamTcp3whsStoreSynApplyToSsn() is called at L2392 unconditionally.
    # The else-branch at L2015 fires:
    #   ssn->flags &= ~STREAMTCP_FLAG_SERVER_WSCALE;  (fixed)
    # Without the ~, this would AND flags to 0x10, wiping 4WHS, TFO, etc.
    Ether(src="00:00:00:00:01:01", dst="00:00:00:00:02:02") / \
    IP(src=C, dst=S) / \
    TCP(sport=cp, dport=sp, flags="S", seq=1000,
        options=[('MSS', 1460)]),

    # ── Packet 4: client SYN/ACK completing the 4WHS ────────────────
    # Without the bug fix: STREAMTCP_FLAG_4WHS was wiped by packet #3,
    # so L2191 rejects this as "stream.3whs_synack_in_wrong_direction".
    # With the fix: 4WHS is still set (packet #2), so this is accepted.
    Ether(src="00:00:00:00:01:01", dst="00:00:00:00:02:02") / \
    IP(src=C, dst=S) / \
    TCP(sport=cp, dport=sp, flags="SA", seq=1000, ack=2001,
        options=[('MSS', 1460)]),

    # ── Packet 5: server ACK completing the handshake ───────────────
    Ether(src="00:00:00:00:02:02", dst="00:00:00:00:01:01") / \
    IP(src=S, dst=C) / \
    TCP(sport=sp, dport=cp, flags="A", seq=2001, ack=1001),

    # ── Packet 6-7: data in both directions ─────────────────────────
    Ether(src="00:00:00:00:01:01", dst="00:00:00:00:02:02") / \
    IP(src=C, dst=S) / \
    TCP(sport=cp, dport=sp, flags="PA", seq=1001, ack=2001) / b"GET / HTTP/1.1\r\nHost: server\r\n\r\n",

    Ether(src="00:00:00:00:02:02", dst="00:00:00:00:01:01") / \
    IP(src=S, dst=C) / \
    TCP(sport=sp, dport=cp, flags="PA", seq=2001, ack=1006) / b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nhello ",
]

wrpcap("stream-flag-wipe-repro.pcap", pkts)
print("Wrote stream-flag-wipe-repro.pcap (%d packets)" % len(pkts))
