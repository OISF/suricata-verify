# lua-luaxform-sandbox-limits

A luaxform script that trips the sandbox memory limit fails the transform
and must count in both the aggregate `transform.lua.errors` and the
category `transform.lua.memory_limit_errors`, mirroring the detect.lua
aggregate-plus-category behavior. The untransformed buffer is kept, so
the rule still matches.

input.pcap: one HTTP/1.1 GET and a 200 response with a small body
(`python3 mkpcap.py input.pcap <b64 body>`).
