# Redmine #8851 FTP expectation allocation failure

Regression test for https://redmine.openinfosecfoundation.org/issues/8851.

The target control flow follows the ticket's passive FTP reproducer: banner,
`USER`, `PASV`, a `227` response selecting port 51210, and `RETR a`. A PCAP
cannot deterministically fail the small `ExpectationList` allocation, so GDB
sets its result to NULL at the ticketed error branch. A first FTP flow creates a
successful expectation and the second flow reaches the injected failure. GDB
then verifies the ticket's required cleanup directly: the failed creation must
call `IPPairRelease` for the exact IP pair it acquired. Before the fix, that
call was absent, leaving the IP pair referenced and locked.

Regenerate the pcap with `./make-pcap.py`. The test is skipped if GDB is not
available or the Suricata binary lacks GDB-readable line information for the
fault-injection breakpoint.
