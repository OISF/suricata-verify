Test that a sub state's default-policy takes precedence over the per-protocol
default-policy.

HTTP/2 hooks live under the stream and global sub states, which gives the
resolution chain an extra tier:

    firewall.policies.app.http2.stream.<hook>
    firewall.policies.app.http2.stream.default-policy
    firewall.policies.app.http2.default-policy
    firewall.policies.app.default-policy
    firewall.policies.default-policy
