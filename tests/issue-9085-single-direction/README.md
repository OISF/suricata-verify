# Issue 9085 — TFTP single-direction app-layer transactions

TFTP builds each transaction from a request datagram observed in the to-server
direction only — `TFTPParseResponse` in `src/app-layer-tftp.c` is documented
"Response parsing is not implemented" and creates nothing — but
`TFTPTransaction::new` in `rust/src/tftp/tftp.rs` created them with
`AppLayerTxData::new()`, which is documented "for a transaction that covers both
directions" and leaves both `SKIP_INSPECT` bits clear. The engine then treated
every TFTP transaction as still needing inspection in a direction it would never
be observed in. Two things followed: the request transaction could be inspected
— and alert — in the to-client direction; and because the to-client inspect bit
could never be set, `AppLayerParserTransactionsCleanup` never freed the
transaction, so a TFTP flow on UDP/69 accumulated transactions without bound and
re-walked the whole list on every packet. The fix creates transactions with
`AppLayerTxData::for_direction(Direction::ToServer)` so the unseen direction
carries `SKIP_INSPECT`.

This is the same defect, and the same one-line shape of fix, that DHCP and RDP
received in 8.0.6 — see `tests/bug-8621`, and commits `bac8a69ca`
("dhcp: mark transactions single-directional to fix tx leak") and `ef035c760`
("rdp: mark transactions single-directional").

Related tickets:
- https://redmine.openinfosecfoundation.org/issues/9085
- https://redmine.openinfosecfoundation.org/issues/8621

## Test cases covered

These tests cover the per-direction inspection correctness, which is the part of
the defect observable in suricata-verify.

- **issue-9085-single-direction-01** — a read request followed by a server ERROR
  on the same flow, with a generic `alert tftp` rule. The request transaction
  must alert only on its own packet. Before the fix the alert on the server
  packet also carried the request transaction (`tftp.packet: read`,
  `tftp.file`, `tftp.mode`), because the transaction was still being inspected
  to-client.

- **issue-9085-single-direction-02** — the same pcap with directional rules
  (`flow:to_server` and `flow:to_client`). TFTP only ever builds a to-server
  transaction, so the to-client rule must never match one. Before the fix it
  matched the request transaction on the server packet.

Both tests need the server-side packet: it is what drives to-client inspection,
which is what exposes the wrong-direction inspection at the alert level. A purely
one-way pcap does not surface the bug in suricata-verify (see below).

## Where the pcap comes from

`issue-9085-single-direction-01/input.pcap` is synthetic. It was built by
`issue-9085-single-direction-01/generate-pcap.py` (Python standard library
only) and was never captured from any network. It is 2 frames / 179 bytes: one
62-byte RFC 1350 read request for `rfc1350.txt` in `octet` mode from
10.0.0.2:40000 to 10.0.0.1:69, and one 61-byte RFC 1350 ERROR ("File not
found") back from 10.0.0.1:69 to 10.0.0.2:40000.

The server's reply is sent **from port 69** rather than from a freshly allocated
transfer TID. A server that refuses outright, without allocating a transfer
TID, answers from 69, and that is what keeps the server packet on the same
5-tuple as the request (reversed, so the same flow) — which is what makes the
to-client inspection of the request transaction observable at all. The two
existing TFTP pcaps in this repo (`output-eve-tftp-01`, `tftp-tx-handling-wrq`)
show the other case: the server answers from an ephemeral port, so the request
flow to UDP/69 carries exactly one packet and is structurally to-server only.

The pcap is classic libpcap, microsecond timestamps, no extensions, so it passes
`pcap-check.sh`.

## Not covered here (and why)

- **The transaction retention itself is not directly assertable in
  suricata-verify.** The leak — transactions never freed, unbounded growth,
  quadratic CPU — has no observable handle in this harness. `app_layer.tx.tftp`
  is a creation counter: it reads identically on a fixed and an unfixed build.
  There is no "tx freed", "tx active", or tx-list-length counter in stats, and
  suricata-verify has no memory or CPU check. Diffing all 529 stats counters
  between a fixed and an unfixed build over a 1000-request one-way pcap moved no
  app-layer or transaction counter at all.

  The leak can however be observed indirectly through the retained transaction:
  the sibling test `tests/issue-9085` replays a request/reply flow with a
  reply-side `udp` rule and `detect.guess-applayer-tx`, and asserts that the
  request transaction retained by the leak is not guessed for the reply alert.
