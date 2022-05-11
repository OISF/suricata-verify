This test is copied from util-action-test-14 with minor changes to check that
Suricata behaves as expected even if there is an alert queue reallocation
failure.

To achieve that, we simulate the alert queue expansion with
``simulate-alert-queue-realloc-failure`` command-line arg and we force the alert
queue max to be 1, since we have a really pcap.

Expected Behavior
=================

As the DROP and ALERT actions have higher priority, we expect alerts for sids
1 and 3. But the alert queue size will mean that the ``alert`` signature will be
discarded.

PCAP
====
pcap generated with scapy.

