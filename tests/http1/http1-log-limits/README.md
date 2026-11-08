# HTTP/1 log limits

Proves the http logger's own bounds: per-field string cap and the
per-direction header budget, both applied to the final value so the
logged size does not depend on how the bytes were split into chunks.

- `string-log-limit`: 16 KiB default, 64 KiB max. A cut string ends with
  `[truncated N additional bytes]`.
- `header-log-limit`: 32 KiB default, 64 KiB max, per direction. Hitting
  it sets `request_headers_truncated` / `response_headers_truncated`.
- `http_request_body`/`http_response_body`: 100 KiB cap per body, sets
  `http_request_body_truncated` / `http_response_body_truncated`.

## Flows

| flow | bytes | expected |
|---|---|---|
| A | `/` + 16991 `A`, one 17-KB segment | `url` cut at 16384 + marker |
| B | same bytes as A, 200-B segments | identical `url` length to A |
| C | 66 x 400-B `X-Forwarded-For` (26530-B concat) | `xff` cut at 16384 + marker |
| D | 34 unique 1-KiB `X-Pad` headers (34340 B) | `request_headers_truncated: true` |

No rule, no MemBuffer drop: worst record here is well under MAX_LIMIT.
`generate_pcap.py` is stdlib-only and deterministic; `http1.pcap` is the
committed output.
