# NFSv4 COMPOUND with a defined but unparsed op

Five well-formed NFSv4.0 `COMPOUND {PUTFH, LOCK}` calls, each answered
`NFS4_OK` (tshark dissects all of them cleanly). `LOCK` is defined by RFC 7530,
but the request parser does not implement it, so the compound fails to parse.

That is unsupported traffic, not malformed traffic. Rejecting every such record
on a transaction of its own logs one `malformed_data` tx and anomaly per
compound for ordinary locking traffic (the same holds for `LOCKU`, `LOCKT`,
`READLINK`, `RESTOREFH`, `SECINFO`, `TEST_STATEID` and the v4.2 ops). The checks
pin that none is logged here.

Regenerate the capture with `python3 gen.py` (deterministic, no deps).
