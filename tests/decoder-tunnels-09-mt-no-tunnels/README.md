# Description

`multi-detect.selector: tunnel` without any `decoder.tunnels` definition can
never select a tenant (every packet has tunnel id 0).
With --init-errors-fatal the engine must refuse to start. The vlan selector
refuses unconditionally when vlan tracking is disabled.

# Ticket

https://redmine.openinfosecfoundation.org/issues/7674

# PCAP

Reuses decoder-tunnels-01 pcap.
