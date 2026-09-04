# NFS size limits with memory-unit suffixes

Same capture as nfs-toolarge-cfg, but the max-write-size / max-read-size
limits are given as 1kb (1024) instead of the bare number 1024. The
byte-valued NFS limits must accept the standard memory-unit suffixes.

Checks: both too-large events fire and both transactions are logged,
exactly as with the numeric values.
