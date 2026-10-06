# smb1-ooo-gap-queue-interleave

Pins that the SMB out-of-order file-data gap backstop inspects **every**
open file transaction, not just the file whose handle is in progress.

The capture is synthetic: the real SMB1 setup (negotiate/session/tree/
create) from the smb1-ooo-read-queue capture, followed by 600 pairs of
READ_ANDX reads. Each pair sends `[req_A1, req_A2, req_B]` in one client
segment and the server answers `[resp_A1, resp_A2, resp_B]` in one
segment (one parse arrival): file A enqueues TWO out-of-order chunks and
file B ONE, with B always enqueued last. File B is a second file
distinguished only by its 2-byte FID in the request (the response FID is
ignored by the parser; the guid comes from the request via
read_offset_cache). The responses for pair 5 are missing (a real TCP
gap, declared by the client's ACKs, no retransmissions cover the hole).

Because the file cursor never advances (offsets start at 1), every
response lands out of order in the FileTransferTracker's chunk map.
After 600 pairs file A holds 1200 OOO chunks (> the 1024 hard cap) while
file B holds 600 (< 1024). The queue limits are disabled (0/0), so the
per-enqueue queue check does not reject and the count backstop is the
only net.

A backstop that only inspects the in-progress file would only ever see
file B (600 < 1024) and never truncate file A, leaving 1200 queued
chunks (and their per-entry overhead) in memory. The scan-based backstop
inspects all open file txs, sees file A at 1200 > 1024, truncates it and
raises exactly one `applayer/smb/truncated_file_data`.

The 1 GiB byte backstop does not fire: 1200 x 8 KiB is well under 1 GiB,
so this test specifically exercises the count dimension on a
non-in-progress file.
