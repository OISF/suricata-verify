Test that `transform_result` does not fire on an absent buffer. The pcap's
GET request has no Referer header and no body. must_error, error_or and
must_succeed after from_base64 on http.referer and http.request_body produce
no alerts, while `absent` on the same buffers fires, confirming the buffers
are absent.
