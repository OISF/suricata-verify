Test
=====

Test and showcase the verdict output for ``alert`` and ``pass`` rules in IDS mode.

Behavior
========

This is a simple test to check that alerts that trigger for a packet that also
triggers a pass rule will show the proper ``verdict.action: pass``, when they
also trigger a ``pass`` rule.

PCAP
====

Pcap comes from test alert-max/alert-max-append-higher-priority and was created
with a scapy script.
