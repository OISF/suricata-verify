Test that packet.default-policy takes precedence over the global default-policy
at a packet filter hook.

Packet filter hook has no setting of its own, so it inherits reject:packet from
packet.default-policy. That action distinguishes the winning tier from the
alternatives: the global default is accept:hook and the built-in filter policy
is drop:packet, so 13 rejected packets rule out both. reject is the only action
that tells the three apart here, which is why the test requires LIBNET1.1.

pre-flow and pre-stream carry accept:hook so the packets survive to reach
filter. The two rules in firewall.rules exist only to install those hooks and
never match.
