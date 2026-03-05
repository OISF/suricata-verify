# Test Description

Test for false blocked alerts when using a `pass ssh` rule with
`geoip` in IPS mode.

Issue: https://redmine.openinfosecfoundation.org/issues/8333

## PCAP

The input trace is based on the pcap provided in the issue
`ssh_capture.pcapng`. To allow the re-use of a minimal test geoip database the
SSH server IP in the trace was rewritten from `13.233.200.203` to
`123.125.71.29` (mapped as `FR` in `test.mmdb`).
