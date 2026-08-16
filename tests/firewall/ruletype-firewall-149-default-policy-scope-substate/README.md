Test that action scope validation covers default policies nested under a sub
state.

The rejected setting is app.http2.stream.default-policy rather than one at the
top of firewall.policies. The error quotes the full nested path, so the check
confirms both that the sub state tier is validated like any other and that the
message points at where the bad setting actually lives.
