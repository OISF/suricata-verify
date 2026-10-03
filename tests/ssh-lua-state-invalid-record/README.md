# ssh-lua-state-invalid-record

Both banners parse, then the server (to-client) direction sends a
record header with pkt_len 0: an invalid record that fails the
direction unrecoverably, frozen in kex. The client direction stays
in kex (it never sends a newkeys record).

- sid 1/2 (`request_banner` / `request_kex` + lua
  `client_proto() == "2.0"`): the client direction reaches kex.
- sid 3 (`request_session`): the client never reaches session: no
  alerts.
- sid 4 (`response_kex` + lua `server_proto() == "2.0"`): the
  server direction reaches kex before the failure.
- sid 5 (`response_session`): the server direction is frozen in
  kex by the invalid record: no alerts.

The failure object itself (server.error = invalid_record,
server.state = kex) is asserted by the dedicated
ssh-eve-invalid-record test; this test keeps the eve output
undisturbed by state hook tracking.

The state hook rules use no port constraint: the rule's direction
and ports are matched per direction, and a to-server-side port
constraint would stop the rule from matching in the to-client
evaluation, where the response hooks run.
