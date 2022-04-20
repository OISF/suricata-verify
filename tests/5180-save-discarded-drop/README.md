Test
====

This test is a sibling of the test to for saving the drop action when there is
an alert queue expansion failure, and was crafted to check that Suri behaves
the same with or without the alert queue expansion failure.

So we have the same checks, without passing the command-line option
'--disable-alert-queue-expand'.

The expected behavior is that the engine will yield same results as the other
tests, that is, trigger the first sid, register the drop of the second sid, and
discard the third alert, as there's no more space left in the queue.

PCAP
====

Pcap from https://forum.suricata.io/t/suricata-5-0-1-in-ips-mode/94/14
Test adapted from bug-4663-03 test.
