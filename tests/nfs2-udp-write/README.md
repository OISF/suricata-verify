# nfs2-udp-write

A v2 WRITE over unmarked UDP (the v2 probe is UDP-only) in the RFC 1094
shape: raw 32-byte file handle, beginoffset/offset/totalcount words and
the XDR-opaque file data (length-prefixed, 8 words shorter than the v3
write args). The preceding LOOKUP pins the v2 reply path; its plain tx
is logged at flow end, after the reply set the state version. The
shared write path must apply the v2 extent (48 + file_len) instead of
the v3 one (fh_len + 24 + file_len) and parse the RFC 1094 WRITERQ2
args; before those fixes a v2 WRITE desynced the record walk and the
file was rejected as malformed instead of logged.

Fixture: `nfs2-udp-write.py` (regenerate with `python3
nfs2-udp-write.py`, the pcap is validated with tshark).
