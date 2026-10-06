# Description

An ENIP request PDU whose 24-byte header and body arrive in separate TCP
segments must be reassembled, not dropped.

An ENIP PDU is a 24-byte header (which carries the body length `pdulen`) followed
by that many body bytes. When the header is delivered in one TCP segment but its
body only arrives in a later segment, `EnipState::parse_tcp()` must return
`AppLayerResult::incomplete()` and wait for the remainder, then parse the
reassembled PDU.

Previously `parse_enip_pdu()` called `take(pdulen)` on the short slice, which on
a complete slice returns `nom::Err::Error(Eof)` rather than `Incomplete`. So
`parse_tcp()` returned `AppLayerResult::err()`, `AppLayerParserParse()` ran its
error path (`StreamTcpDisableAppLayer(f)` + `AppLayerParserSetEOF(pstate)`), and
app-layer parsing was disabled for the whole flow -- the split PDU and everything
after it went uninspected. This is the ENIP/CIP inspection bypass this test
guards against.

# Reproduction

`input.pcap` (built by `writepcap.py`) carries the *same* two ENIP PDUs on two
TCP flows to port 44818:

* a `ListIdentity` request (`cmd 0x0063`, empty body), and
* a `SendRRData` request (`cmd 0x006f`) carrying an unconnected CIP
  `Get_Attribute_List` (service `0x03`) on class `0x8b`.

Flows:

* **Contiguous** (client port 40001): both PDUs in a single 74-byte segment.
* **Split** (client port 40002): the first segment holds `ListIdentity` plus only
  the 24-byte `SendRRData` header; the `SendRRData` body arrives in a second
  segment, so the PDU is reassembled across two segments.

Both flows must produce identical results: the CIP request is decoded, the
`cip_service`/`enip_command` keywords match, and an eve `enip` record with the
CIP service is logged. Wireshark likewise dissects the CIP on both flows
(reassembling the split one). Before the fix, only the contiguous flow was
inspected; the split flow's `SendRRData`/CIP was bypassed.

The CIP request bytes are reused from `tests/enip-keywords/enip_cip_example.pcap`.
