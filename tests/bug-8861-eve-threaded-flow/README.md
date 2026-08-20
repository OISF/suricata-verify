# bug-8861-eve-threaded-flow

## Purpose

Regression test for Redmine #8861: a double-free during teardown of threaded
EVE output.

During the init phase (LogFileNewThreadedCtx), threads shared prefix/sensor
names through a shallow copy.
During deinit, all threads attempted to free the variables.
Suricata would then crash as a result of a double free.


## PCAP

The traffic is irrelevant to the bug, the pcap only needs to produce EVE alert
and flow records.
