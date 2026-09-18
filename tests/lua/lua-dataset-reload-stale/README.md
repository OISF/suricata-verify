Reproducer for lua/dataset: the Lua dataset handle stores a raw
non-owning Dataset* cached on first use. Static sets (rule load=) are
freed on rule reload by DatasetPostReloadCleanup(), but output lua states
are created once at startup and are not reinitialized, so the cached
handle dangles and add() operates on freed memory.

The test feeds a paced pcap through a FIFO: batch 1 lets the output
script resolve and cache the Dataset handle, then SIGUSR2 triggers a
rule reload (freeing the static set), then batch 2 drives add() through
the stale handle. ASAN: heap-use-after-free in SCDatasetAdd; plain
build: SIGSEGV.

Ticket: #9054.
