# ssh-lua-state-basic

State hooks for a well-formed SSH session in both directions,
checked with lua assertions.

The pcap completes the session in both directions (banners plus a
newkeys record each way) and ends with no client ACK, so the
transaction is logged at flow end after all data has been parsed.
Every state hook is reachable in both directions:

- sids 1-3 (`request_banner`, `request_kex`, `request_session`):
  the to-server direction reaches each state; the lua asserts the
  client proto version through `ssh.get_tx()`.
- sids 4-6 (`response_banner`, `response_kex`, `response_session`):
  the to-client direction reaches each state; the lua asserts the
  server proto version.

The eve check asserts the transaction logs both banners with no
error field.

The state hook rules use no port constraint: the rule's direction
and ports are matched per direction, and a to-server-side port
constraint would stop the rule from matching in the to-client
evaluation, where the response hooks run.
