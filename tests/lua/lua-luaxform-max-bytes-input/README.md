# lua-luaxform-max-bytes-input

The fixed max-bytes cap (baseline + max-bytes) counts the input buffer
the engine pushes before the call, so a same-size luaxform of a 100 KB
buffer fails at max-bytes 300000 (transform.lua.memory_limit_errors,
untransformed buffer kept, no alert). Before the fixed cap the call's
setup pushes were exempt; this pins that they still are.

input.pcap: one HTTP/1.1 GET and a 200 response with a 100000-byte body
(`python3 mkpcap.py input.pcap 100000`).
