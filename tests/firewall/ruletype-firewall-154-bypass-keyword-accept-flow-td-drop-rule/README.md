Expectation
-----------

Test that the engine maintains "the "firewall" and "IPS" work as two distinct
devices" premise in a scenario where the same flow packet triggers an
`accept:flow+bypass` firewall rule and a `drop packet` threat detection rule.

As the firewall rule would be evaluated and processed first in the scenario of a
separate device, the td rule shouldn't drop the packet -- as it wouldn't even
"see" that packet, as a separate device.

This test mirrors `ruletype-firewall-141` but adds the TD `drop` rule to check
for this corner case.

Pcap
----

Reused from `flowbit-oring` test.

Ticket
------

Related to https://redmine.openinfosecfoundation.org/issues/8459.

