NFS name and record size bounds.

RFC 1813 3.2 declares ``filename3<>`` and ``nfspath3<>`` unbounded, so a v3 name
can be as large as stream reassembly allows and it is the logger that has to
bound what it writes. RFC 1094 3.6 does bound a v2 name at MAXNAMLEN (255).

The v3 stream carries a 4 KiB CREATE name (logged whole, under the 8 KiB per
field cap), a 40 KiB LOOKUP name and a RENAME with a 70 KiB source and 20 KiB
target (shortened to the cap with the in-value marker, record marked
``nfs.truncated``). The RENAME source is logged twice, as ``filename`` and as
``rename.from``, so the budget has to be charged for what is written: charging
the parsed length dropped the field although the record was well inside it.

The v2 stream carries a 300 byte name: ``malformed_data`` and the whole name in
the log, which is the only place either version flags a name at parse level.
