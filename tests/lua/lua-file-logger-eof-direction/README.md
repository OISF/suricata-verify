# lua-file-logger-eof-direction

One http transaction with a file in each direction (a multipart upload
and a download), both bodies truncated, and the pcap ends without
FINs. At end of pcap Suricata forces the reassembly pseudo passes: a
tosearch pseudo for the pending ts stream and a toclient pseudo (the
last one, i.e. eof) for the tc stream, and the file loggers run from
those passes. The lua file handle must anchor the logger's dir - the
file container's direction - not the running packet's: on the eof
pass the two containers are driven from pseudo packets and each file
has to resolve against its own container.

Pins the file-handle direction plumbing: a handle anchored to the
packet's direction resolves the wrong container on the passes where
the two differ (for parsers that use the same track id in both
directions, such as http2, that would even return the other
direction's file).
