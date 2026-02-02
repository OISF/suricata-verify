Test `absent: must_error` across multiple buffers with from_base64.
Validates must_error on URI with strict mode (decode error) combined
with content matching on http.host, and verifies no match when rfc2045
decode succeeds.
