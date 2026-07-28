Test that packet.default-policy takes precedence over the global default-policy
at a packet filter hook.

Packet filter hook has no setting of its own, so it inherits reject:packet from
packet.default-policy. That action distinguishes the winning tier from the
alternatives: the global default is accept:hook and the built-in filter policy
is drop:packet.
