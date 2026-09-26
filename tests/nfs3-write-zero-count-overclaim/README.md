# nfs3-write-zero-count-overclaim

Pins the record boundary for zero-count v3 WRITE records: the extent/claim
check runs before the `count == 0` early return, and a claim above the
parsed extent is the record tail rather than malformed data, so the
zero-count arm skips silently to the record boundary instead of dropping
it.

Before the fix the early return ran first: the handler consumed only the
parsed args, and the claimed remainder (512 bytes of junk) was parsed as
a new RPC record on the next segment, desyncing the stream; the
following well-formed WRITE was never parsed.

The capture is synthetic: a well-formed 100-byte v3 WRITE (attach,
establish the handle), then a zero-count WRITE (count 0, file_len 0,
claim overreaches the 96-byte extent by 512), split so the first segment
carries only the args (partial-record path, rec_size 612 >= 512); the
second segment carries the junk remainder followed by a well-formed
1000-byte WRITE (xid 0x44444444) on the second handle.
Regenerate: `python3 gen.py` (scapy).

Checks: the following WRITE parses (nfs event with rpc.xid 0x44444444),
its 1000-byte file is extracted intact (sha256 checked), and no
`truncated_file_data`. The zero-count record itself is expected to log
nothing: the skip is silent.

tshark note: the zero-count record dissects normally: tshark parses the
args, resyncs on the record boundary and dissects the next call in the
same segment. The WRITE replies use the simplified 20-byte layout (verf,
count, offset, stable) shared with the other synthetic v3 write tests, so
tshark flags those 2 reply packets as [Malformed Packet]; that is expected
for this generator's convention.
