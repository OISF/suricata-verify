# nfs-config-filter-empty

`app-layer.protocols.nfs.filter` given as an **empty** YAML list. The key
being present is what switches off the built-in "hide v3 GETATTR" default, so
with `filter: []` everything is logged, GETATTR included. This is the case
that would fault if the list walk assumed a value on the sequence node.

the capture is `nfs3-01`'s, referenced as `../nfs3-01/input.pcap`.
