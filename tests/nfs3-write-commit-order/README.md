Status of an UNSTABLE WRITE closed by a COMMIT
==============================================

An UNSTABLE WRITE split into two chunks is closed by a COMMIT. Whether the
record carries the writes' status depends on the order the replies arrive in,
because COMMIT is what completes the transaction.

- flow B (port 952) is what a client that waits for each write reply before the
  next call produces: the error is in hand when the COMMIT lands, so the record
  reports `ERR_IO` / 5.
- flow A (port 951) pipelines both writes and the COMMIT, and the replies come
  after. The COMMIT logs the record first, so `nfs.status` is left out
  altogether - the writes' error arrives too late to reach it.

The file record of flow A is the other half of the story: it is written when the
file closes and keeps the default `OK`, with no `status_code`. It describes the
file, not an RPC reply, so an `OK` there must not be read as "the write
succeeded" - the WRITE record of the same flow reports no status at all.

Clients normally wait for the write replies before committing, so flow B is the
common case; flow A is in here to pin what Suricata does when they do not.

`gen.py` writes `input.pcap`. Regenerate with `python3 gen.py`.
