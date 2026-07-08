# app-layer-protocol-list-prefilter-invalid

Verifies that an explicit `prefilter;` on a multi-value (pipe-separated)
`app-layer-protocol` keyword is rejected at rule load. A multi-value keyword
stores its values in a bitmask that the single-valued prefilter bucket key
cannot represent, so forcing prefilter would bucket the rule under
`ALPROTO_UNKNOWN` and silently never match. The rule must therefore fail to
load with a clear error instead.
