# Redmine #8009 NFSv3 FILE_SYNC WRITE file extraction

Regression test for https://redmine.openinfosecfoundation.org/issues/8009,
which has the same root cause as
https://redmine.openinfosecfoundation.org/issues/9196.

`input.pcap` is the first 85 packets of `test_nfsv3.pcap`, the capture
attached to the ticket (sha256
`ff2a603c6fa1bb74c836512479d45826f97990431f89b22ef3fbb7e517671095`), cut
with:

    editcap -r test_nfsv3.pcap input.pcap 1-85

It holds one NFSv3 TCP connection, which starts before the capture does, so
the test enables `stream.midstream`. The client looks up and creates
`test.doc`, writes all 71680 bytes of it with a single FILE_SYNC WRITE whose
RPC record spans many TCP segments, then looks up and creates `test.docx`.
The cut ends before the first WRITE to `test.docx`.

Before the fix, a FILE_SYNC WRITE was taken as the last chunk of its file and
its file transaction was closed as soon as the first segment of the record
was parsed. The rest of the file data then found no open transaction and was
parsed as an RPC record header. The file was TRUNCATED at 12528 bytes, NFS
logged `malformed_data` and a parser error, and NFS parsing was disabled for
the rest of the connection, so the `test.docx` LOOKUP and CREATE were not
seen.

Fixed behavior: `test.doc` is CLOSED with all 71680 bytes and the SHA-256 of
the WRITE data, its content past the first 12528 bytes matches a `file.data`
rule, the LOOKUP and CREATE of both files alert, and there are no NFS parser
errors or `malformed_data` events.
