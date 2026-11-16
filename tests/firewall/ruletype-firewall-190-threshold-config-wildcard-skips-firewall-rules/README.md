Expectation
-----------

A wildcard ``suppress`` entry must not error out just because the ruleset has
firewall rules. The firewall rules are skipped with a single summary warning,
while threat detection rules are suppressed as usual.

This is what separates the wildcard case from a config entry naming a firewall
sid directly, which is fatal at startup.

Pcap
----

Reused from `flowbit-oring`, HTTP request to www.testmyids.com.

Ticket
------

Related to https://redmine.openinfosecfoundation.org/issues/8459.
