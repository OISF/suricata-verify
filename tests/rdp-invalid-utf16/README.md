# rdp-invalid-utf16

Pins the strict UTF-16 handling of RDP Client Core Data fields.

`RDP-invalid-utf16.pcap` is the stock `rdp-protocol` capture
(`tests/rdp-protocol/RDP-003.pcap`) with the 32-byte client name in the
Client Core Data child of the MCS Connect-Initial patched to invalid
UTF-16LE (an unpaired surrogate `D8 00` followed by zero padding). The
TCP checksum of the patched segment is recomputed so the packet is
accepted.

Pinned behaviour (identical to `main`):

* `le_slice_to_string()` (rust/src/rdp/util.rs) converts the
  UTF-16LE field with a **strict** conversion. The invalid name makes
  the Client Core Data child fail to parse.
* The `connect_request` RDP event is still logged (the rest of the
  MCS Connect-Request parses), but it carries **no** `client` block.

This guards against converting the field with a lossy conversion
(e.g. `to_string_lossy()`): that would let the parse succeed and log a
`client` block containing U+FFFD replacement characters, which is
visible to detection and EVE output and changes parser behaviour on
network input.
