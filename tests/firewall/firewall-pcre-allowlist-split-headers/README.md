# A firewall rule without a fast pattern waits for its state to complete

Allow-list at `request_headers` written with `pcre` only: `http.host; pcre:"/good\.example/";`, so no
prefilter gates it. The request headers span two segments, split inside the Host header. The miss on the
first segment must not be final: the `request_headers` default policy (drop:flow) must not decide before
the headers are complete, and the rule matches on the second segment. Before the fix the request was
dropped at the first segment.
