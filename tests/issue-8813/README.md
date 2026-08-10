# Redmine #8813 SMTP file-open failure

Regression test for https://redmine.openinfosecfoundation.org/issues/8813.

The pcap reaches the MIME file-open path for the first SMTP attachment in a
transaction. The attachment is named `x.bin`. Because an allocation failure
cannot be requested through network traffic, `fail-file-open.gdb` makes the
first call to `FileOpenFileWithId()` return `-1`.

A fixed build handles the failure, finishes processing the SMTP flow, and does
not log a `fileinfo` event. A vulnerable build passes the missing file to
`SMTPNewFile()` and terminates. The test is skipped when GDB or the required
`FileOpenFileWithId` symbol is unavailable.

The pcap was generated with Scapy:

    ./make-pcap.py -o input.pcap
