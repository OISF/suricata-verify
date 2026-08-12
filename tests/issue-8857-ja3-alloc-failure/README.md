# Redmine #8857 JA3 allocation failure ownership

Regression test for https://redmine.openinfosecfoundation.org/issues/8857.

The pcap contains the ticket's TLS ClientHello with a `supported_groups`
extension. A PCAP cannot deterministically exhaust the allocator, so the GDB
script waits until the elliptic-curve helper is active and then makes the
first JA3 data allocation appear to have failed. Before the fix, only the
helper's by-value pointer was cleared and the caller reused and freed the
dangling buffer. The fixed double-pointer path clears caller ownership and
exits safely.

Regenerate the pcap with `./make-pcap.py`. The test is skipped if GDB is not
available.
