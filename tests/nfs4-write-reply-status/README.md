# nfs4-write-reply-status

Covers the status of an UNSTABLE NFSv4 WRITE that has an answer.

One v4 COMPOUND WRITE of 100 bytes at offset 0 with `stable` set to UNSTABLE,
and its reply: `NFS4_OK`, count 100, committed FILE_SYNC as the server echoes
it. UNSTABLE leaves the file transaction open for a later COMMIT, so nothing
marks it last, and the reply used to be dropped: only a FILE_SYNC write
recorded the xid the reply path matches on, so an answered write could be
logged with no status at all even though the server had said OK.

`gen.py` regenerates `input.pcap`. tshark reads it as a V4 Call WRITE and a
V4 Reply WRITE with no malformed frames; the WRITE result carries count,
committed and the 8 byte write verifier.

Pinned: the WRITE record with `status: OK` and `status_code: 0`, and the flow
resolving to NFS. No file record is pinned: the data comes from the request,
and whether the file reaches storage is the tracker's, not the status rule's.
