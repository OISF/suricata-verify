Test `absent: must_error` across multiple buffers with pcrexform.
Validates that a must_error condition on one buffer (request_line)
combined with content matching on another buffer (http.host) works
correctly.
