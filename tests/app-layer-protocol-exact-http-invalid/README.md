# app-layer-protocol-exact-http-invalid

Verifies that `app-layer-protocol:http,exact` is rejected at rule load. The
generic `http` (ALPROTO_HTTP) is never a flow's classified protocol (flows are
`http1`/`http2`), so an exact `http` match could never fire; the keyword rejects
it with an error pointing to `http1`/`http2`.
