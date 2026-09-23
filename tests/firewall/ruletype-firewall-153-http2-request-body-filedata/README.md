Test that a firewall LTE rule using file_data becomes a final no match once
the http2 request has moved past the file_data engine's progress (request
closed), so the fail-closed default policy (drop:flow) is applied before
the stream/tx has completed.

The pcap is an HTTP/2 session with one POST stream; the request body (a
plain text file, no %PDF) is fully uploaded and the request is closed
(packet 8, DATA with END_STREAM) while the response is left open, so the
stream/tx never reaches its end state on its own. This is the "streaming
registration" case from the fix: before
"detect/file-data: report a final no match at engine eof" the engine kept
returning NO_MATCH, the LTE rule never became definitive and the fail-closed
default policy was never applied, so the flow was not dropped.

http2 uses two substates: the connection (global) hooks are accepted via
explicit rules; the fail-closed policy is configured only for the stream's
request-data hook.

Run: `python3 gen_input_pcap.py` to regenerate input.pcap.

The tests also assert `fileinfo` records so the files under inspection are
verified to be tracked and closed complete.
