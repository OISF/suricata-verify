# Description

Reproducer for Redmine #8619: app-layer transaction cleanup is indefinitely
delayed when a `pass` rule matches a UDP flow.

Commit `d8ddef4c` ("detect: delay tx cleanup in some edge case", Ticket #7552)
added a condition in `AppLayerParserTransactionsCleanup` that delays
transaction cleanup until detection has run with the correct signature group
head (`FLOW_SGH_TOCLIENT` / `FLOW_SGH_TOSERVER`).

When a `pass` rule matches a UDP flow, `FLOW_ACTION_PASS` makes `DetectFlow()`
skip all subsequent packets in both directions. `FLOW_SGH_TOCLIENT` is never
set and `APP_LAYER_TX_INSPECTED_TC` is never marked, so completed transactions
are never freed for the lifetime of the flow. On long-lived UDP flows (e.g.
continuous SNMP polling, or any UDP app-layer protocol) this causes unbounded
memory growth.

# Reproduction

A pure memory leak is hard to assert on directly, so this test makes the
accumulation observable through a parser that bounds its live transactions.

The pcap is a single CLDAP (LDAP-over-UDP) flow with:

- 4 complete searchRequest/searchResponse pairs (message_id 1-4). These are the
  transactions that should be freed once complete.
- 3 trailing searchRequests with no response (message_id 5-7).

With `app-layer.protocols.ldap.max-tx=4`, correct cleanup frees each completed
pair as it finishes, so the live-transaction list never exceeds the cap.

Under the bug, the `pass` rule stops detection, the 4 completed transactions are
never freed, the list grows past `max-tx`, and the LDAP parser raises the
`too_many_transactions` app-layer event. That event is logged as an `anomaly`
record (independent of detection, which is why it survives the `pass`).

The check asserts the `too_many_transactions` anomaly is absent: the test FAILS
on the buggy code and PASSES once cleanup is fixed.

# PCAP

Generated from the CLDAP payloads in `../ldap-udp/cldap.pcap`, replayed on a
single UDP 4-tuple with incrementing LDAP message_ids.
