Test
====

This test was crafted to check the behavior of the Suricata engine when the
AlertQueueExpand function fails.

To achieve that, we use the ``--disable-alert-queue-expand`` command-line
option.

The expected behavior is that the engine will continue to run, logging alerts
that could not be queued as ``discarded``, and saving the first valid ``DROP``
signature it sees.

PCAP
====

Pcap from https://forum.suricata.io/t/suricata-5-0-1-in-ips-mode/94/14
Test adapted from bug-4663-03 test.
