The trailer block ends with the indexed HPACK field 0, which RFC 7541 section 6.1
forbids. The field before it decodes and reaches `http.trailer`; the failed one has
no name or value and is logged as `{"error": "HTTP2HeaderDecodeIndex0"}` in
`http.request_trailers`. The test fails on EVE schema validation unless the trailer
and header array item schemas accept that `error` key.
