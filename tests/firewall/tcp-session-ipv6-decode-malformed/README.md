Test that an IPv6 decode-layer event (decoder.ipv6.exthdr_useless_fh) fires
for a malformed IPv6 fragment header regardless of whether a tcp.session:
accept rule matches the surrounding flow.
