# IPv4 option presence with `ipopts:any`

Replay four UDP packets: IPv4 without options, IPv4 with NOP, IPv4
with Record Route, and IPv6 without extension headers. The packets use
distinct source ports; the UDP control rule confirms that all four were
inspected. The option-presence rule must alert exactly once on each
IPv4 packet with options, and on neither of the other packets.

The PCAP is synthetic. To regenerate it, run `python3 make-pcap.py`
with no third-party packages.

Redmine: https://redmine.openinfosecfoundation.org/issues/9423
