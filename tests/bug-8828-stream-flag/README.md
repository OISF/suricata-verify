# stream-tcp-flag-wipe-fix: Regression test for missing `~` in StreamTcp3whsStoreSynApplyToSsn

**Bug:** `src/stream-tcp.c`, function `StreamTcp3whsStoreSynApplyToSsn()`.

When a queued or retransmitted SYN lacks the TCP Window-Scale option, line
2016 originally executed:

    ssn->flags &= STREAMTCP_FLAG_SERVER_WSCALE;   /* BUG: preserves only bit 4 */

instead of the correct:

    ssn->flags &= ~STREAMTCP_FLAG_SERVER_WSCALE;  /* CLEAR only bit 4 */

This ANDs `ssn->flags` with `0x10`, zeroing every other flag already set on
the session — notably `STREAMTCP_FLAG_4WHS`, `STREAMTCP_FLAG_ASYNC`,
`STREAMTCP_FLAG_CLIENT_SACKOK`, and `STREAMTCP_FLAG_TCP_FAST_OPEN`.

**Impact:** In a simultaneous-open (4-way) handshake, the wipe of
`STREAMTCP_FLAG_4WHS` causes the completing SYN/ACK to be rejected as
"3way handshake SYNACK in wrong direction" (`sid:2210003`), and the session
never reaches ESTABLISHED. Data bypasses stream reassembly and app-layer inspection.

## Test scenario (4-packet 4WHS)

1. Client → Server SYN with WScale + SACK
2. Server → Client bare SYN (starts 4WHS, sets STREAMTCP_FLAG_4WHS)
3. Client → Server SYN retransmit, **no** WScale ← triggers the else-branch bug
4. Client → Server SYN/ACK completing 4WHS

Without the fix, packet #4 is rejected with `stream.3whs_synack_in_wrong_direction`.
With the fix, the session proceeds normally.

## Reproducer

See `generate-repro.py` for the Scapy script that builds this pcap.
