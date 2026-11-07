# nfs3-fsinfo-ceiling

v3 FSINFO reply with the RFC 1813 3.3.19 `FSINFO3resok` layout
(post_op_attr + rtmax/rtpref/rtmult/wtmax/wtpref/wtmult/dtpref/
maxfilesize/time_delta/properties) advertising a 4 KiB max transfer
size, then a 1 KiB READ (in range) and an 8 KiB FILE_SYNC WRITE (over
the ceiling). The write request raises the advisory
`fsinfo_too_large` anomaly while the file data is still tracked
(fileinfo size 8192). Pins the FSINFO reply layout fix: before it the
reply parsed a fabricated field order and the advertised ceiling was
never stored.

Fixture: `nfs3-fsinfo-ceiling.py` (regenerate with `python3
nfs3-fsinfo-ceiling.py`, the pcap is validated with tshark).
