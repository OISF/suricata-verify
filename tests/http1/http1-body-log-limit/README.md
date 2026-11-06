# HTTP/1 body log limit

Proves the http body logger cap survives a config that removes every
parser-side bound.

- `request-body-limit: 0` and `stream.reassembly.depth: 0` let htp store
  the full 5-MiB request body.
- Alert metadata (`http-body`, `http-body-printable`) logs the body; the
  test sets `http-body-log-limit: 16 KiB` (default 100 KiB, max 256 KiB)
  so the cap is reachable without a >100-KiB inspection window.
- Both representations stop at 16384 B (base64 21848 chars) and
  `http_request_body_truncated` is true.
- The rule matches at body offset 60000 so the alert is built after the
  body has grown past the cap.

`generate_pcap.py` is stdlib-only and deterministic; `http1.pcap` is the
committed output.
