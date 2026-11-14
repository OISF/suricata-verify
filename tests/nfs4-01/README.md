PCAP
====

Pcap from https://wiki.wireshark.org/SampleCaptures#NFS_Protocol_Family

The capture also carries the v4.1 backchannel: the server sends a CB_NULL
call to the client on its own connection and the client answers. That is
valid traffic, so the test pins that no nfs anomaly comes out of it in
either direction.
The v4.1 session fields are pinned too: every record of the flow carries
`nfs.minorversion: 1` and the `nfs.client_id` the EXCHANGE_ID and
CREATE_SESSION replies assign, so a compound that stops reading the minor
version, or a session op that stops assigning the client id, fails here
instead of logging those fields out thin. EXCHANGE_ID and CREATE_SESSION are
pinned with both fields set on the record, because either one reaching
`client_id` is enough to make the aggregate check pass on its own.
