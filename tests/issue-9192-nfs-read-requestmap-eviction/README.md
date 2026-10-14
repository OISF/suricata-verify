# Redmine #9192 NFS READ continuation lost by request map eviction

Regression test for https://redmine.openinfosecfoundation.org/issues/9192.

Each flow sends an NFSv3 READ whose 560 byte reply record arrives in two
segments: 200 bytes (RPC and READ headers plus 152 bytes of file data) and
a 360 byte continuation. The continuation is valid file data, but it starts
with `00 00 00 10`, an invalid RPC record marker (fragment length 16) if it
is ever parsed as a new record. After the continuation the client sends a
LOOKUP and a second READ whose 20 byte file holds `NFSMAP_FILE_MARKER`.

- Client port 41011, control: a single NULL call is sent while the
  continuation is pending.
- Client port 41012: 521 NULL calls (distinct xids) are sent after the
  first reply segment, pushing the READ xid out of the 512 entry request
  map before the continuation arrives. Any `max-requests` up to 521
  reproduces.

The test pins `app-layer.protocols.nfs.max-requests=512` in `test.yaml`.
That is the current default, but pinning it keeps the eviction flow
evicting the READ xid if the default is ever raised above 521.

Before the fix the active READ was only reachable through the request map.
With its xid evicted, the continuation was parsed as an RPC header, the
parser failed and NFS parsing stopped for the flow: the initial file was
TRUNCATED at 152 bytes, and the LOOKUP and second READ were not inspected
(raw TCP content rules still matched).

The fixed parser keeps the active READ file handle independently of the
request map, so both flows behave the same: the initial READ file is
CLOSED with all 512 bytes (sid 9192005 matches the continuation bytes in
`file.data`), the LOOKUP and the second file alert, and there is no
`malformed_data` anomaly or NFS parser error.

The capture is shared with `issue-9192-nfs-read-tx-eviction`, which
replays it with other NFS limits.

The capture was recorded from a scripted NFSv3 client and server.
