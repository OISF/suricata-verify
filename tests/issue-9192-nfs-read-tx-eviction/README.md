# Redmine #9192 NFS READ continuation after its transaction is evicted

Regression test for https://redmine.openinfosecfoundation.org/issues/9192.

This test has no capture of its own: `test.yaml` replays
`../issue-9192-nfs-read-requestmap-eviction/input.pcap`. That capture holds
an NFSv3 READ reply split into a 200 byte first segment (152 bytes of file
data) and a 360 byte continuation that starts with an invalid RPC record
marker, then a LOOKUP and a second 20 byte READ. Client port 41011 is the
control flow; on port 41012, 521 NULL calls are sent while the
continuation is pending.

This test covers the other way the continuation can lose its file.
`max-requests=1024` keeps every xid in the request map, and `max-tx=64`
makes the NULL calls force-close the oldest open transaction: the
partially received READ file (tx_id 0, `too_many_transactions`). Any
`max-tx` up to 520 reproduces; 64 evicts early in the burst and stays well
above the control flow's four transactions.

Before the fix the continuation found no open file transaction, was parsed
as an RPC header, and NFS parsing stopped for the flow (parser error,
`malformed_data`, no LOOKUP or second READ alerts).

Fixed behavior: the evicted file stays TRUNCATED, holding the 152 bytes
received before the forced close (the size is not asserted). The
continuation is skipped to the known record boundary without being added
to any file, and the LOOKUP and second READ are parsed and alert on both
flows with no NFS parser error.
