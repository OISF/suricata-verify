# Redmine #8860 NFSv4 SECINFO_NO_NAME cursor

Regression test for https://redmine.openinfosecfoundation.org/issues/8860.

The RPC call seeds the NFSv4 COMPOUND XID map. Its reply contains the ticket's
two operations: a successful `SECINFO_NO_NAME` with one `AUTH_SYS` flavor,
followed by a successful READ carrying `EVILDATA`. Before the fix, the flavor
bytes were returned as unconsumed input and reinterpreted as the second opcode,
so the READ was lost. A fixed parser exposes `EVILDATA` to `file.data` and the
rule alerts.

The generator computes RPC record-marker lengths from the encoded records;
this corrects the hand-counted marker values in the ticket while preserving
its exact NFS fields. Regenerate with `./make-pcap.py`.
