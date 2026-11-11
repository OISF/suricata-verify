# NFSv3 TCP: record slack must not reach the transfer size

A WRITE or READ that spans reassembly buffers is delivered to the parser in
chunks, and the segment that completes a record can carry bytes past the file
data: the XDR pad of the reply and, with pipelined calls, a record of its own.
The chunk path is handed all of that, so the file transaction size has to count
the file bytes the tracker took, not the length of the input it was called
with.

One connection, client 192.168.1.10:941 to server 192.168.1.20:2049:

```
W1 WRITE xid 1  FH_A offset    0  2000 bytes 0x41   call claim 2116
W2 WRITE xid 2  FH_A offset 4096  3000 bytes 0x42   call claim 3116
R1 READ  xid 3  FH_B offset    0  4099 bytes        call claim 108, reply 4144
R2 READ  xid 4  FH_C offset    0    64 bytes        call claim 108, reply 108
```

to server a: W1 whole, then W2's marker, args and first 2000 file bytes.
to server b: W2's last 1000 file bytes, then the R1 and R2 calls whole.
to client c: R1's marker, header (status, attributes, count, eof, data length)
and the first 4000 data bytes.
to client d: R1's last 99 data bytes and its byte of XDR pad, then R2's reply
whole.

So the two calls that end a record are also the two that carry foreign bytes:
W2's completing call is handed 1224 bytes for 1000 file bytes, R1's 212 for 99.
The sizes must be what each file transaction is owed - 2000 for W1, 3000 for
W2, 4099 for R1, 64 for R2 - where counting the input would log 3224 and 4212.
The WRITEs go unreplied and complete from the request side, as the parser does
from 9.0 on.

`nfs3-ooo-write-queue-tail-slack` pins the same accounting for the queue
limits; this one is for the logged sizes.

Regenerate the capture with `python3 gen.py` (deterministic, no deps).

Checks: one record per call with those four sizes, at 0, 1, 2 and 1 chunks,
and no NFS anomaly. The files are not stored (the harness runs with
`--disable-detection`), so the records are the whole pin.

tshark note: the calls all dissect (`tshark -r input.pcap
-d tcp.port==2049,rpc`); R1's reply shows as malformed because it is split
across two segments on purpose, like the other segmented NFS captures here.
