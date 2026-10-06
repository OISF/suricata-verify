# nfs3-write-toolarge-claim

Pins the v3 WRITE too-large skip to the RPC record boundary. The first
record claims 16384 bytes but carries only 2000 (`max-write-size=4096`);
a second, benign WRITE follows in the same stream. Claimed-count
arithmetic (`count - received`) would skip 14384 bytes into later records
and desync the parser; boundary arithmetic skips the padding only, so the
second record is logged and its file is stored intact.
