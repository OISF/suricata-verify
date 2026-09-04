# Terminal backward FILE_SYNC write must truncate the file

NFSv3: per handle, an in-order UNSTABLE WRITE of 100 bytes establishes
the file, then a FILE_SYNC WRITE at a lower (already tracked) offset
retransmits an already tracked region. That data is never flushed (the
queue only drains chunks keyed at the tracked offset), so the file can
no longer be completed. The retransmission path used to clear the
chunk's is_last and strand the file open until flow teardown while the
NFS caller marked the transaction closed. The tracker now truncates at
the terminal backward write. Pins: each of the three files logged
TRUNCATED with the in-order 100 bytes, all mid-flow (pcap_cnt present).
