# app-layer-protocol-legacy-equivalence

Verifies that legacy (non-firewall) `app-layer-protocol` detection rules keep
the historical `AppProtoEquals()` protocol equivalences for backward
compatibility. The capture is classified as `doh2` (DNS over HTTP/2), which is
equivalent to both `dns` and `http2`. A `dns` or `http2` keyword therefore
matches the flow, while `!dns` and an unrelated `tls` keyword do not.

Firewall rules intentionally match exactly (no equivalence widening); that
behavior is covered by the tests under `tests/firewall/app-layer-protocol-*`.
