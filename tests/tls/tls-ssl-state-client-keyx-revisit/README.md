# tls-ssl-state-client-keyx-revisit

Pins that `ssl_state:client_keyx` fires once the ClientKeyExchange is
processed, even though the keyword was already evaluated (and missed) at the
started state when the hello began.

`ssl_state` lives on the shared `tls_generic` buffer, registered at progress 0
for both directions. The prefilter only revisits an engine when its progress
bookkeeping allows it; once the tx moved past progress 0 the engine was
skipped and the `client_keyx` state was never inspected - a state-tracking
evasion. The buffer is now marked run-always, so the engine is evaluated on
every tx update and sees the state the ClientKeyExchange sets.

The fixture is `tls-client-hello-frag-01/dump_mtu300.pcap` (a full TLS 1.2
handshake). The ClientKeyExchange is in frame 22; the keyword is evaluated on
the first app layer update after it (frame 23), which is where the alert is
pinned.
