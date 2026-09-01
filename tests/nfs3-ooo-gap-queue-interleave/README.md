# nfs3-ooo-gap-queue-interleave

Pins that the NFS out-of-order file-data gap backstop inspects **every**
open file transaction, not just the most recently enqueued file.

The capture is synthetic: a TCP handshake followed by 600 pairs of
NFSv3 READ calls. Each server arrival (one TCP segment) carries
`[reply_A1, reply_A2, reply_B]`: file A enqueues TWO out-of-order chunks
and file B ONE, and B is always enqueued last, so the "most recently
enqueued" file handle is always B's. The replies for pair 5 are missing
from the capture (a real TCP gap, declared by the client's ACKs, no
retransmissions cover the hole).

Because the file cursor never advances (offsets start at 1), every reply
lands out of order in the FileTransferTracker's chunk map. After 600
arrivals file A holds 1200 OOO chunks (> the 1024 hard cap) while file B
holds 600 (< 1024). The queue limits are disabled (max-read-queue-
size/cnt = 0), so the per-enqueue queue check does not reject and the
count backstop is the only net.

A backstop that only inspects the most recently enqueued file would only
ever see file B (600 < 1024) and never truncate file A, leaving 1200
queued chunks (and their per-entry overhead) in memory. The scan-based
backstop inspects all open file txs, sees file A at 1200 > 1024,
truncates it and raises exactly one `applayer/nfs/truncated_file_data`.

The 1 GiB byte backstop does not fire: 1200 x 2 KiB is well under 1 GiB,
so this test specifically exercises the count dimension on a
non-last-enqueued file.
