# Evicted file transactions must release their file

1100 handles each open a file with one in-order WRITE, so the NFS
transaction list exceeds NFS_MAX_TX (1024). Every new transaction then
evicts one open transaction. The evicted transaction's file tracker is
truncated at eviction time so the file logger releases the file and its
queued data immediately, instead of holding it open (and its memory
live) until flow teardown. Pins: exactly 75 TooManyTransactions
evictions, all 75 evicted files logged TRUNCATED mid-flow (pcap_cnt
present), all 1100 files eventually logged.
