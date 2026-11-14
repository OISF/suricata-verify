# nfs4-write-overlap

Covers `file_overlap` on an NFSv4 write.

Two UNSTABLE WRITEs to the same handle: 100 bytes at offset 0, then 50 bytes
at offset 50. The second starts inside the region the file tracker already
holds, so the copy Suricata inspects is not the one the server keeps: the
overlapped bytes stay as written by the first call. The v2 and v3 paths
raised `file_overlap` there, the v4 path did not, so the write was dropped
by the tracker with nothing in EVE to say so.

`gen.py` regenerates `input.pcap`. Only the requests are needed: the overlap
is a property of the write offsets, and UNSTABLE keeps one file transaction
open across both writes so the second reaches the tracker that holds 100
bytes. tshark reads the capture as two V4 Call WRITE records with offsets 0
and 50, each with the count and the opaque data, and no malformed frames.

Pinned: the anomaly; one WRITE transaction whose offset is 0 and whose size is
150, which is what the shared chunk rule appends - the bytes past the tracked
end - rather than what the server stored; that no transaction reports 100
bytes, which is what a per-write transaction would look like; and the flow
resolving to NFS - a parser must not lose detection to raise an event. No
`fileinfo` is expected: without replies the file closes with the flow, which
is what the flow check covers.
