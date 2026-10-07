Test Description
================

Elephant flow where only the toclient direction exceeds the rate-tracking
threshold. The flow must be logged as elephant, with only the toclient
direction, and only the toclient and either rules must match.

On 8.0.x this also covers the backport keeping FLOW_IS_ELEPHANT as the either
direction flag, with the per direction state tracked separately.

PCAP
====

Generated with gen-toclient-elephant.py (scapy).

Redmine Tickets
===============

https://redmine.openinfosecfoundation.org/issues/8117
https://redmine.openinfosecfoundation.org/issues/9179
