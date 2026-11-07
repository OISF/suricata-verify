# nfs-config-filter

Covers `app-layer.protocols.nfs.filter` given as a YAML list (the config
parse in `SCNfsTxParseConfig` and the decision in `SCNfsTxLoggingIsFiltered`).

the capture is `nfs3-01`'s, referenced as `../nfs3-01/input.pcap`. Without the key the
build-in default hides v3 GETATTR; with `filter: [lookup]` GETATTR must
appear and LOOKUP must not, so the test fails if the list is ignored,
mis-parsed, or merely added to the default.
