# nfs4-gss-unwrap-fail

NFSv4 over RPCSEC_GSS with the `integrity` service (creds procedure 0 =
`RPCSEC_GSS_DATA`, service 2) wraps the COMPOUND in an envelope, per RFC 2203
5.3.2.2: the length of the wrapped body (sequence number and arguments), the
sequence number, the arguments, then the checksum. Suricata unwraps before
parsing the compound, and when the envelope cannot be unwrapped it stopped
there: the reject was a *state* event, which stamps the newest transaction in
the state and does nothing at all when the state has none.

Four flows, each a different face of that:

- `939` — the first RPC of the flow is an integrity CALL whose envelope length
  is outside the 4096-byte credentials bound. Nothing had been parsed yet, so
  there was no transaction to stamp: the call went by with no transaction, no
  anomaly, nothing in EVE. A good compound follows.
- `940` — same shape, but the length is inside the bound and past the end of
  the record: the unwrap comes back incomplete, which takes the other arm.
- `941` — an async mount: two integrity calls (A then B), both opening a
  transaction, then A's reply with a broken envelope while B is still open,
  then B's reply. B is the newest transaction at the moment of the failure, so
  the event was stamped on it: an anomaly carrying B's `tx_id`, while A - the
  call actually rejected - stayed open. The event must be on A (`tx_id` 0),
  there must be exactly one on the flow, and both transactions must close.
- `944` — an integrity call of a compound that opens no transaction at all
  (PUTFH+GETATTR: no main-opcode result), then its reply with a broken
  envelope. The reject needs a transaction of its own, and that one has to
  carry the procedure the request map recorded: left at 0, EVE logs it as
  `NULL` for what was a COMPOUND reply.

Red before the fix, on v24 `3b9ea9db2`: sub tests 1 and 3 find no event at all, 6
finds the anomaly on `tx_id` 1 (the wrong call) and 9 finds nothing for the
transactionless compound. Sub test 10 is red on the first revision of the fix,
where the fallback tx was left at procedure 0 and EVE read it as NULL.

`gen.py` regenerates the capture deterministically.
