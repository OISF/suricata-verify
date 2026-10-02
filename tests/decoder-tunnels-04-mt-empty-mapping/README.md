# Description

A multi-tenant tunnel mapping with an empty `tunnel-id:` value must be
rejected as a configuration error, not crash the engine.

# Ticket

https://redmine.openinfosecfoundation.org/issues/7674

# PCAP

Reuses decoder-tunnels-01 pcap.

# Lukas review comment

Just a config update to not crash the whole Suricata