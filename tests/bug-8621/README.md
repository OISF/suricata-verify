# Issue 8621 — single-direction app-layer transactions

DHCP (and RDP) build each transaction from a message observed in a single
direction, but created them with both `SKIP_INSPECT` bits clear. The engine
then treated every transaction as still needing inspection in the direction it
would never be seen in. Two things followed: a transaction could be inspected —
and alert — twice, once per direction; and on a flow that only ever carries one
direction the never-observed direction's inspect bit could never be set, so
`AppLayerParserTransactionsCleanup` never freed the transaction (unbounded tx
growth and O(n^2) CPU). The fix creates transactions with
`AppLayerTxData::for_direction()` so the unseen direction carries `SKIP_INSPECT`.

Related tickets:
- https://redmine.openinfosecfoundation.org/issues/8621
- https://redmine.openinfosecfoundation.org/issues/8658

## Test cases covered

These tests cover the DHCP half of the fix — specifically the per-direction
inspection correctness, which is the part observable in suricata-verify.

- **bug-8621-01** — a DHCP request/reply exchange and a generic `alert dhcp`
  rule must produce one alert per datagram (two total), not one per direction
  (four). Guards against a transaction being inspected/alerting in both
  directions.

- **bug-8621-02** — the same request/reply pcap with directional rules
  (`flow:to_server` and `flow:to_client`). The to-server rule must match only
  the request and the to-client rule only the reply; neither may fire on the
  other transaction. Guards that each transaction carries the correct
  per-direction `SKIP_INSPECT` bit.

Both tests use a bidirectional (request + reply) pcap by necessity: the reply
packet is what drives to-client inspection, which is required to expose the
wrong-direction inspection before the fix. A unidirectional pcap would not
surface the bug at the alert level.

## Not covered here (and why)

- **RDP is unit-test only.** RDP receives the same `for_direction()` change, but
  it has no observable suricata-verify delta: it has no per-transaction
  detection keyword, a bare `alert rdp` over TCP matches per packet (not per
  transaction), and RDP bounds its transactions to connection setup so it does
  not leak. Running identical rules on the RDP-fixed and RDP-unfixed binaries
  produces byte-identical alerts, so an s-v test would pass equally before and
  after the fix. The RDP change is covered by the Rust unit test
  `test_tx_skip_inspect_direction` in `rust/src/rdp/rdp.rs`, which asserts the
  per-direction `SKIP_INSPECT` flags directly. The DHCP unit test of the same
  name in `rust/src/dhcp/dhcp.rs` does the same for DHCP.
