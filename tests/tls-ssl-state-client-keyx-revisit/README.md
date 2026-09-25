# tls-ssl-state-client-keyx-revisit

`ssl_state` is evaluated from the live handshake state, not from a snapshot
buffer: the rule sees the state move from `client_hello` to `client_keyx` and
must be revisitable, so it alerts on the Client Key Exchange packet (23).

The rule carries a prefilterable content so the signature is walked per packet;
the generic-list engine's P + 1 finality must not turn the earlier misses into a
permanent no match for a stateful keyword. `ssl_state` is marked
`SIGMATCH_STATEFUL`, which exempts it from that finality.
