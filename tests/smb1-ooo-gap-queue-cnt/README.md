# smb1-ooo-gap-queue-cnt

Pins the SMB out-of-order file-data **chunk-count** backstop.

The capture is synthetic: a real SMB1 setup (negotiate, session setup, tree
connect, create of \poc.bin) followed by 1150 sequential 8 KiB READ_ANDX
reads. The responses for reads 5-6 are missing from the capture (a real
TCP gap on the server->client direction, declared by the client's ACKs),
and no retransmissions cover the hole.

Because the file cursor never advances (the first read starts at offset 1),
every response lands out of order in the FileTransferTracker's chunk map.
The queue limits are disabled (max-read-queue-size/cnt = 0), so the
per-enqueue queue check does not reject; instead the OOO chunk count grows
unboundedly until it exceeds the 1024 hard cap (the backstop fallback when
the count limit is disabled: 16x the default queue count of 64). At that
point the tracker truncates the file and raises
`applayer/smb/truncated_file_data`.

The 1 GiB byte backstop does not fire here: ~1145 x 8 KiB of OOO data is
well under 1 GiB, so this test specifically exercises the count dimension.
