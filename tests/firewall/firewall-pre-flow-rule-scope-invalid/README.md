Test that firewall rules on the pre_flow hook reject the "flow" and "tx"
action scopes at load time. pre_flow runs before Suricata has a flow, so
only "packet" and "hook" scopes are valid, the same as for the
firewall.policies.packet.pre-flow default policy.
