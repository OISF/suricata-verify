# Redmine #9196 NFS split FILE_SYNC WRITE closes its file early

Regression test for https://redmine.openinfosecfoundation.org/issues/9196,
which has the same root cause as
https://redmine.openinfosecfoundation.org/issues/8009.

The capture has three NFSv3 over TCP flows. Each sends an 800-byte WRITE,
then a REMOVE:

| Client port | WRITE |
| --- | --- |
| 34632 | DATA_SYNC, split after the first 48 bytes of file data |
| 43218 | FILE_SYNC, in one segment (control) |
| 43234 | FILE_SYNC, split after the first 48 bytes of file data |

A WRITE record of 512 bytes or more that arrives incomplete is parsed
partially, and the rest of its file data is expected as a continuation.
Before the fix, a partial FILE_SYNC (`stable = 2`) WRITE closed its file
transaction on the first segment, so the 752-byte continuation on 43234 found
no open transaction and was parsed as an RPC record header. That parse error
disabled NFS parsing for the rest of the flow: the file was truncated at 48
bytes, NFS logged `malformed_data` and a parser error, and the REMOVE did not
alert. A raw TCP rule still saw the REMOVE.

Fixed behavior: all three flows alert on the REMOVE, the split FILE_SYNC file
is CLOSED with all 800 bytes and the same SHA-256 as the one-segment control,
and there are no NFS parser errors or `malformed_data` events. The DATA_SYNC
WRITE never sends a last chunk or a COMMIT, so its file stays open and is
logged as TRUNCATED at the end of the flow with all 800 bytes.

Wireshark reports the WRITE and REMOVE calls as malformed because the 9-byte
file handle has no XDR padding. Suricata does not need the padding, and the
defect reproduces the same way with aligned handles (see
issue-9196-nfs-filesync-partial-append).
