# nfs4-read-claim-record-tail

Pins the record tail of a **complete** v4 READ reply: the claim covers the
bytes the record holds past the parsed body, the stream advance walks the
claim, and the file tracker is left with no fill.

Here the reply's claim (572) is 8 bytes past its body (564); the parsed
extent is 532 bytes, so all 8 are record tail. Nothing of that tail may
reach the file, and because the record is complete nothing of it stays
unbuffered either, so the next chunk for the same handle (offset 512, eof)
continues the same file. A tracker left armed with `fill_bytes` would take
the `fill_bytes != 0` arm there and truncate the file instead.

Upstream's `issue-9194-nfs-xdr-pad-read` covers the same record tail on its
own (a padded reply followed by the record of a different file, in every
delivery shape). This test is the other half of that promise: the tail plus
the chunk continuation of the same file.

The capture is synthetic: a small v4 getattr exchange (attach), a READ
request (offset 0, 512), the reply with the record tail (512 x 0x77), and a
second READ request/reply (offset 512, 512 x 0x88, eof) on the same handle.
Regenerate: `python3 gen.py` (scapy).

Checks: no NFS anomaly, one READ file transaction logged under the first
request (0x33333333) with `last_xid` set to the second reply (0x44444444),
and the file completing as 512 x 0x77 + 512 x 0x88, CLOSED and stored
(sha256 checked).

tshark note: all records dissect normally
(`tshark -r input.pcap -d tcp.port==2049,rpc`); the tail is inside the
record the marker describes, so the following record starts where the claim
says it does.
