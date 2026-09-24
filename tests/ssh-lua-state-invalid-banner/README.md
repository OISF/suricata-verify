# ssh-lua-state-invalid-banner

A server whose SSH identification line is not a valid banner. The
server (to-client) direction fails unrecoverably (invalid_banner)
and is frozen in the banner state; the client direction parses a
valid banner (the client keeps sending, including a newkeys record).

- sid 1/2 (`request_banner` / `request_kex`): the client direction
  parses its banner; each rule's lua asserts the client proto
  version through `ssh.get_tx()`.
- sid 3/4 (`response_kex` / `response_session`): the hooks of the
  frozen server direction never open: no alerts.

The failure object itself (server.error = invalid_banner,
server.state = banner) is asserted by the dedicated
ssh-eve-invalid-banner test; this test keeps the eve output
undisturbed by state hook tracking.

The state hook rules use no port constraint: the rule's direction
and ports are matched per direction, and a to-server-side port
constraint would stop the rule from matching in the to-client
evaluation, where the response hooks run.
