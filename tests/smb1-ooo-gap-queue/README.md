# smb1-ooo-gap-queue

SMB1 over TCP with a mid-stream TCP sequence gap (the input.pcap is a
splice of the original capture with 10 ToClient packets dropped, leaving a
13855-byte hole that spans response boundaries).

With `max-read-queue-size=4096` the queue limits must keep rejecting the
oversized in-flight read data on the gapped stream: at least one
`read_queue_size_exceeded` anomaly. This pins that the gap handling
(interaction with the OOO-queue backstop in the file tracker) does not
silently disable the configurable queue limits.
