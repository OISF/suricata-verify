# Redmine #9196 NFS split FILE_SYNC WRITE to an open or new file

Regression test for https://redmine.openinfosecfoundation.org/issues/9196
(same root cause as https://redmine.openinfosecfoundation.org/issues/8009).
It covers both file transaction branches of the NFSv3 WRITE handling,
continuations that take more than one segment, and a split FILE_SYNC WRITE
to a file that it truncates.

| Client port | Traffic |
| --- | --- |
| 40001 | UNSTABLE WRITE of 512 bytes, then a 1024-byte FILE_SYNC WRITE to the same open file, split after 200 bytes of file data |
| 40002 | As 40001, FILE_SYNC WRITE in one segment (control) |
| 40003 | 1024-byte FILE_SYNC WRITE as the only chunk, split into 3 segments (200, 400 and 424 bytes of file data) |
| 40004 | As 40003, FILE_SYNC WRITE in one segment (control) |
| 40005 | As 40003, split into 2 segments; the REMOVE shares the second segment with the end of the file data |
| 40006 | UNSTABLE WRITE of 512 bytes, then a 1024-byte FILE_SYNC WRITE at offset 1024, leaving a hole, split after 200 bytes of file data; then a 128-byte FILE_SYNC WRITE at offset 0 to the same handle that starts with a marker |
| 40007 | As 40006, the FILE_SYNC WRITE after the hole in one segment (control) |

Every flow ends with a REMOVE. All file data lengths are multiples of 4, so
no XDR padding is involved.

Before the fix, the first segment of a split FILE_SYNC WRITE closed the file
transaction, both when it opened a new file and when it appended to an open
one. The continuation then found no open transaction and was parsed as an RPC
header, which disabled NFS parsing for the flow. The file was truncated, NFS
logged `malformed_data` and a parser error, and the REMOVE did not alert.

On 40006 and 40007 the FILE_SYNC WRITE after the hole is the last chunk of a
file with missing data, so the file tracker truncates the file. A truncated
tracker never completes, so the file transaction (opened by the UNSTABLE
WRITE and continued by the split WRITE) must still be closed once all of the
split WRITE's file data has been seen. If it stays open, the marker
WRITE is added to the truncated file instead of starting a new one: its data
is not inspected and no file is logged for it.

Fixed behavior: every flow alerts on the REMOVE, and every split flow logs
the same files as its one-segment control. The files of 40001-40005 are
CLOSED with all of their data (1536 bytes for 40001/40002, 1024 bytes for
40003-40005). On 40006/40007 the first file is TRUNCATED at 512 bytes, and
the marker WRITE starts a new file in its own transaction: it is CLOSED with
all 128 bytes, and its data matches a `file.data` rule. There are no NFS
parser errors or `malformed_data` events.

Regenerate `input.pcap` with `./make-pcap.py` (Scapy). The script prints the
expected file sizes and hashes.
