# HTTP/2 decoded header limits

Proves the parser thresholds and logger bounds on decoded HTTP/2 headers:

- parser: `max-header-list-size` 64 KiB (RFC 7540 6.5.2 accounting:
  name + value + 32 per field), `max-header-count` 1024,
  `max-header-field-size` 16 KiB. Exceeding a threshold raises the
  `HeaderListTooLarge` app-layer event; every header is still decoded and
  inspected (no truncation, HPACK table stays in sync).
- logger: 16 KiB per header field and 32 KiB per direction; cuts set
  `request_headers_truncated` / `response_headers_truncated`.

## Flows

| tx | encoding | expected |
|---|---|---|
| `/a` | 25 x 2000-B literal headers (~51 KiB decoded) | logger cuts at 32 KiB, marker set |
| `/b` | 2000-B dynamic entry + 40 x 1-byte indexed refs (~81 KiB decoded) | `HeaderListTooLarge` event, no truncation |
| `/c` | reference to the entry inserted while decoding `/b` | `x-amplify` resolves, proving table sync |

`generate_pcap.py` is stdlib-only and deterministic; `http2.pcap` is the
committed output, checked with `tshark -d tcp.port==443,http2`.
