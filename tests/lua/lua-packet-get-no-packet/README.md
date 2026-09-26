# lua-packet-get-no-packet

Cover test for `suricata.packet.get()` in an app-layer (tx) context where
there is no packet. It must return nil plus the error message
"failed to get packet" (not a stale/leaked packet from a previous
packet-phase inspection). This guards the structural change that the packet
registry entry is written unconditionally. Identical behavior on the unfixed
and fixed trees (contract cover, green on both).
