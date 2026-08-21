Test that a `suppress` entry covering a firewall rule withholds its alert, and
that the rule's accept still takes effect. A scoped suppress means "suppressed,
but still apply the actions", so the alert must go and the accept must stay.

Twin threat detection rules (100001 suppressed, 100002 not) confirm the suppress
config loaded, so a firewall alert appearing cannot be mistaken for an unread
config file.

Pcap: `flowbit-oring/input.pcap`, HTTP request to www.testmyids.com.
