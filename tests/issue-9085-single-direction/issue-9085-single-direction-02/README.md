# issue-9085-single-direction-02

Redmine ticket: https://redmine.openinfosecfoundation.org/issues/9085

A to-client rule must never match a TFTP transaction.

TFTP only ever builds to-server transactions. With the per-direction
SKIP_INSPECT bit set, a `flow:to_client` rule cannot match one. Before the
fix it matched the request transaction on a server packet of the same flow.

Uses the pcap from `../issue-9085-single-direction-01/`.
