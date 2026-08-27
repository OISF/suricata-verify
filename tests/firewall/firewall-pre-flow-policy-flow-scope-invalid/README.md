Test that the firewall.policies.packet.pre-flow default policy rejects the
"flow" action scope at startup. pre-flow runs before Suricata has a flow, so
only "packet" and "hook" scopes are valid.
