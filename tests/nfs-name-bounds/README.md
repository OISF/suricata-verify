NFS logger bounds an EVE record (RFC 1813 names over 1024 bytes).

Names are kept whole on the transaction so `nfs.name` and `nfs.filename` can
match past the protocol bound, which leaves the logger with strings whose size
is only limited by stream reassembly. Here a v3 stream carries a 4 KiB CREATE
name, a 40 KiB LOOKUP name and a RENAME with two 20 KiB names. Each is past the
1024-byte NFCString3 limit so it raises `malformed_data`, the 4 KiB one is still
logged whole, and the rest come back at the logger's 8 KiB cap with an in-value
truncation marker and `nfs.truncated` set on the record.
