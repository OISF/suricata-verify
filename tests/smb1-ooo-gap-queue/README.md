# smb1-ooo-gap-queue

Pins that the SMB read queue limits are enforced on a **gapped** stream.

The capture is synthetic: a real SMB1 setup (negotiate, session setup, tree
connect, create of \poc.bin) followed by 1150 sequential 8 KiB READ_ANDX
reads. The responses for reads 5-6 are missing from the capture (a real
TCP gap on the server->client direction, declared by the client's ACKs),
and no retransmissions cover the hole.

With the default queue limits (max-read-queue-cnt = 64), the per-enqueue
check rejects reads once the out-of-order chunk count reaches the limit:
`applayer/smb/read_queue_cnt_exceeded` (and/or `read_queue_size_exceeded`
if the byte limit is hit first). This pins that the queue limits keep
working on gapped flows, where the reassembler delivers whole responses at
once and the OOO queue grows through the tracker's new_chunk path.
