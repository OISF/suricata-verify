# nfs3-setattr-sattr3

A v3 CREATE (UNCHECKED) resolving "cfile" with a full RFC 1813
CREATE3resok reply, then a SETATTR on the created handle using the
RFC 1813 3.2.4 `sattr3` layout: no mode/uid/gid/size, atime
SET_TO_CLIENT_TIME (the 8-byte `nfstime3` rides inside the set_atime
union), mtime SET_TO_SERVER_TIME, `sattrguard3` unchecked. The SETATTR
response fileinfo resolves the created name, proving the record walk
stays in sync. Pins the sattr3/time_how layout fix: before it the
unions were parsed as flat bool-flagged words (and the client time as
12 bytes instead of the 8-byte nfstime3), so a client-time update
desynced the record walk.

Fixture: `nfs3-setattr-sattr3.py` (regenerate with `python3
nfs3-setattr-sattr3.py`, the pcap is validated with tshark).
