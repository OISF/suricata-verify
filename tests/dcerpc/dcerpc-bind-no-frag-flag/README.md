# DCERPC dcerpc.iface PFC_FIRST_FRAG missing false positive

## Purpose
This test verifies that the `dcerpc.iface` keyword does not generate a false positive match on unrelated UUIDs when the client omits the `PFC_FIRST_FRAG` flag in the DCERPC BIND PDU.

The PCAP contains two connections to port 135:
1. BIND without `PFC_FIRST_FRAG` (`pfc_flags = 0x00`), followed by REQUEST opnum 42.
2. BIND with `PFC_FIRST_FRAG` (`pfc_flags = 0x03`), followed by REQUEST opnum 42.

Both bindings are for the EPM interface (`e1af8308-5d1f-11c9-91a4-08002b14a0fa`).
SID 1 uses a dummy interface (`22222222-2222-2222-2222-222222222222`) and should not alert on either.
SID 2 uses the EPM interface and should alert on both.

## PCAP Origin
The PCAP (`input.pcap`) was captured against a real Windows Server 2022 endpoint.

## Related Tickets
- Redmine #8457
