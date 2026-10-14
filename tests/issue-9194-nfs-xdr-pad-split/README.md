# Redmine #9194 NFSv3 WRITE split XDR padding (capture from the ticket)

Regression test for https://redmine.openinfosecfoundation.org/issues/9194
(stable backport https://redmine.openinfosecfoundation.org/issues/9195),
using the capture from the ticket (a bridge capture) as `input.pcap`.

## Trigger shape

Two NFSv3/TCP flows send the same structurally valid UNSTABLE WRITE (32-byte
handle, `count == file_len == 415`, all 415 data bytes, and the one required
XDR pad byte since 415 is not 4-byte aligned) followed by the same LOOKUP for
`NFSXDRPAD` under that handle. The WRITE record is 516 bytes, so it takes the
partial-record fast path.

- Control flow (sport 55734): the 516-byte WRITE, including its pad byte,
  arrives in one segment, then the 96-byte LOOKUP.
- Attack flow (sport 36492): the first segment is 515 bytes and ends on the
  last file-data byte, so the single XDR pad byte starts the next segment,
  ahead of the identical LOOKUP.

The parser counts only unread file data in its stream continuation
(`ts_chunk_left`), not the XDR pad that the file tracker still owes. When the
segment boundary lands on the last file byte, the continuation finishes with
the pad unconsumed; the pad is then read as the first byte of the next RPC
record marker, which records `nfs malformed_data`, returns a fatal parser
error, and stops NFS inspection for the rest of that flow.

## Fixed expectation

Both flows parse the LOOKUP and alert (`sid:9903101`, `nfs_procedure:3`). The
LOOKUP bytes reach the sensor on both flows via raw TCP (`sid:9903102`), so the
alert loss is a parser desync rather than a missing packet. Each flow's WRITE
file holds exactly 415 bytes, confirming the pad is not file data; because the
WRITE is UNSTABLE with no COMMIT, the file state is TRUNCATED at flow end on
both flows. No `malformed_data` anomaly and `app_layer.error.nfs_tcp.parser`
is 0.

## Baseline (vulnerable) behavior

On `main` @ 4badfd13f4 the control flow alerts on the LOOKUP; the attack flow
does not, records one `malformed_data` anomaly, and produces one NFS parser
error. Both WRITE files still show 415 bytes. The test fails on the baseline on
exactly the attack-flow LOOKUP alert, the anomaly count, and the parser-error
stat.

`input.pcap` is the capture from the ticket, reused unmodified.
