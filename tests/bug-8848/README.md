# Test Purpose

Test that FTP commands padded with trailing whitespace leave the global FTP
memuse counter unchanged.

`CopyCommandLine` allocated a buffer for the whole request line, stripped the
trailing whitespace, and returned the reduced length. That reduced length is
what the caller stores in `tx->request_length` and what `FTPTransactionFree`
hands to `FTPFree`, so one byte per stripped whitespace character was never
taken off `ftp_memuse`. The heap itself is fine -- `SCFree` ignores the size --
but the counter grows for the life of the process.

`FTPCheckMemcap` refuses any allocation that would cross
`app-layer.protocols.ftp.memcap`, so the inflated counter stops just below the
cap instead of passing it. The request buffer is the first allocation to fail:
the transaction is still created, but `tx->request` stays NULL, so
`command_data` is missing from the log and rules that inspect it stop matching.
Whether a new flow can still allocate its state depends on how much room is
left below the cap.

## PCAP

The client sends 30 `USER a` commands padded with 1000 trailing spaces, each
answered with `331 password`. A second, ordinary FTP session follows on a
different port. The memcap is set to 16 KiB via `args`, which sits between the
two sides: with the accounting fixed, the padded flow keeps all 30
`command_data` values even with the cap as low as 640 bytes, and the full set
of events with it as low as 896 bytes; with the accounting broken, the same
flow leaks exactly 30000 bytes, 1000 per command.

Run `python3 writepcap.py` to regenerate `input.pcap`.

## Checks

`stats.ftp.memuse` is 0 at exit -- the direct statement of the bug; the broken
parser ends at 15000 here, or 30000 with no memcap configured. The 30 padded
commands are all logged with `command_data` set, where the broken parser
manages only 15: its request-buffer allocations start being refused 15 commands
into the flow. The later flow is parsed. The broken parser manages that too at
this cap, so the check records what is expected rather than catching the
regression.

Note what this test does not cover. `command_data` is `a` rather than `a` plus
the padding under any version of the fix that strips before copying, including
one that leaves `line->len` itself padded, so these checks say nothing about
the in-place truncation that `PORT`/`EPRT` parsing, the transfer file name and
the too-long-line check depend on. `FTPParserTest14` in `src/app-layer-ftp.c`
covers that.

Redmine 8848.
