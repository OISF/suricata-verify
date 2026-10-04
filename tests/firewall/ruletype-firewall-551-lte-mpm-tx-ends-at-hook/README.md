# LTE rule that cannot match, transaction that ends at its hook

The request completes its header block in the last data packet of the flow, so
the transaction sits at `request_headers` and never advances. The rule hooked
there has a pattern that is absent, so the state must be decided by the default
policy rather than by an implicit accept.

`gen_input_pcap.py` regenerates `input.pcap` (scapy only). Validate with
`tshark -2 -r input.pcap -d tcp.port==80,http -Y http.request`.
