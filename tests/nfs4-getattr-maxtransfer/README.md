# nfs4-getattr-maxtransfer

A v4 GETATTR reply advertising maxread 1024 / maxwrite 2048 via
FATTR4_MAXREAD/FATTR4_MAXWRITE (bits 30/31; the bitmap word[0] covers
bits 0-31; uint64 values), then a 4096-byte WRITE. The write request
raises the advisory `fsinfo_too_large` anomaly while the file data is
still tracked (fileinfo size 4096). Pins the v4 max-transfer tracking
fix: before it the attribute constants were 40/42 and the bitmap
words were combined in the wrong order, so the advertised ceiling was
never stored.

Fixture: `nfs4-getattr-maxtransfer.py` (regenerate with `python3
nfs4-getattr-maxtransfer.py`, the pcap is validated with tshark).
