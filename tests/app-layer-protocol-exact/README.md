# app-layer-protocol-exact

Verifies the `exact` option of the `app-layer-protocol` keyword. The capture is
classified as `doh2` (DNS over HTTP/2). By default `dns` keeps the historical
`AppProtoEquals()` equivalence and matches the `doh2` flow; with `,exact` the
match is strict identity, so `dns,exact` does not match `doh2` while
`doh2,exact` does.
