Test `transform_result` on an absent buffer. The pcap's GET request has no
Referer header and no body. error_or after from_base64 on http.referer and
http.request_body fires, as absent: or_else would; must_error and
must_succeed do not. `absent` on the same buffers fires, confirming the
buffers are absent.
