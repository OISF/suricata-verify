# Redmine #8833 single-entry SYN queue rotation

Regression test for https://redmine.openinfosecfoundation.org/issues/8833.

With `stream.max-syn-queued: 1`, the four ticket-described SYN packets use
distinct sequence numbers and timestamp values. The third packet rotates a
one-element queue; the fourth entered `AddAndRotate` with a NULL head and
crashed before the fix. Successful processing of all four packets is the
regression oracle.

Regenerate the pcap with `./make-pcap.py`.
