Header blocks ended by FIN rather than by a blank line must still be
inspected through http.header.raw; both directions, since neither completion
hook runs when the block never finishes.

Regenerate with `python3 make-pcap.py`.
