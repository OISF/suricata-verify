NFSv3 overlapping WRITE chunks
==============================

A client writes 100 bytes at offset 0, then 50 bytes at offset 50, to the same
file, both UNSTABLE so the file transaction stays open across them. The second
write starts inside what the file tracker already holds, which `file_overlap`
reports. The v2 and v3 write paths raised it from the start; the check exists
here so the v4 path (tests/nfs4-write-overlap) can be seen to agree with them,
and so a change to the accounting rule shows up on both versions.

The transaction logs offset 0 (the write that opened it) and size 150, the bytes
both calls carried - `nfs.write.size` sums the payloads, so the overlapping half
counts twice. `fileinfo.size` is what the tracker kept, 100, and the overlap
event is what marks the difference.

`gen.py` writes `input.pcap`; both writes answer OK so the transaction closes
with a status. Regenerate with `python3 gen.py`.
