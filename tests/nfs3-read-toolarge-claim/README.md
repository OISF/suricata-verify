# nfs3-read-toolarge-claim

Pins the v3 READ reply too-large skip to the RPC record boundary. The
first reply claims 16384 bytes but carries only 2000 (`max-read-size=4096`);
a second, benign READ request/reply follows. The rejected reply must
complete its transaction (log with the event) and skip to the record
boundary only, so the following records parse cleanly and the second
file is stored with the right content.
