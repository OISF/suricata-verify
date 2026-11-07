PCAP
====

Pcap from https://wiki.wireshark.org/SampleCaptures#NFS_Protocol_Family

The capture also carries the v4.1 backchannel: the server sends a CB_NULL
call to the client on its own connection and the client answers. That is
valid traffic, so the test pins that no nfs anomaly comes out of it in
either direction.
