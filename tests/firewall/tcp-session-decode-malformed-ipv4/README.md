Test that a decode-layer event (decoder.ipv4.opt_invalid_len) fires for a
malformed IPv4 packet regardless of whether a tcp.session: accept rule
matches the surrounding flow.
