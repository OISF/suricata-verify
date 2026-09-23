Test that a firewall LTE rule using file_data becomes a final no match once
the DATA tx has moved past the file_data engine's progress, so the
fail-closed default policy (drop:flow) is applied on the tx.

The session sends one MIME text attachment that does not contain the content
the rule looks for (%PDF). For smtp the engine's eof coincides with the tx's
end state, so the drop also happened before
"detect/file-data: report a final no match at engine eof" (via the tx end
state path); this test pins the fail-closed behavior. The discriminating
streaming case (eof before the tx end state) is covered by
ruletype-firewall-153-http2-request-body-filedata.

Run: `python3 gen_input_pcap.py` to regenerate input.pcap.

The tests also assert `fileinfo` records so the files under inspection are
verified to be tracked and closed complete.
