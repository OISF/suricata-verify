Regression test: a v3 LOOKUP reply split across two TCP segments must
be parsed (not skipped), so the looked-up filename reaches the namemap
and the response fileinfo. A client ACK separates the segments so the
stream engine feeds the app layer the partial record first.
Regenerate: python3 nfs3-lookup-segmented.py (imports nfs_sv_common.py).

Note: tshark flags the reassembled reply [Malformed Packet] — a tshark
v3 LOOKUP RPC-reassembly dissector exception; the unsplit reply of the
same content parses cleanly and the reassembled frame shows the valid
LOOKUP reply.
