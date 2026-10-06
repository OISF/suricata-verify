Expectation
-----------

Test that `bypass` on a firewall `accept:flow` rule is terminal, especially when
the competing TD rule is a *packet* rule.

Firewall rule sid:103 accepts and bypasses the flow at the
`http1:request_headers` hook. The threat detection rule sid:100003 would match
against the same packet and could drop it, but shouldn't, just as it would happen
with the firewall in a separate device. The IPS rules cannot act on an unseen
packet.

Difference from ruletype-firewall-150
-------------------------------------

Test 150 uses an `http` TD rule, which lands in the *app* detect table and is
inspected inside `DetectRunTx`, after the firewall rule on the same transaction.
The bypass therefore suppresses it and 150 passes.

This test uses `tcp-pkt`, forcing the TD rule into the *packet* detect
table. This explores the scenario with Packet rules, which are inspected in `DetectRulePacketRules`, which runs before
`DetectRunTx`. We're then checking that a TD alert that would be queued before
the firewall rule matched and the bypass applied won't affect the firewall's bypass.

sid:100001 would alert on the HTTP response body if the flow were still being
inspected, and must not alert: the flow left inspection at the request headers.

Pcap
----

Reused from the `flowbit-oring` test.

Ticket
------

Related to https://redmine.openinfosecfoundation.org/issues/8459.
