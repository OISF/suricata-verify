Test `transform_result: error_or` on http.request_body with from_base64. The
pcap has three POST bodies: invalid base64, base64 of "This is malicious
content", and base64 of "This is benign content". Every rule fires on the
invalid body's decode error. Sid 2 also fires on the malicious body through
its content, so it fires twice; sids 1 and 3 have content that no body
decodes to, so they fire once.
