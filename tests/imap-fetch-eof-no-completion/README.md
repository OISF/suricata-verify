Email header fields (`email.subject`, `email.from`, ...) and `imap.response` are
inspected at transaction completion, which for the to-client side is the tagged
reply. A server that sends a full FETCH literal and then closes the connection
without the tagged `A1 OK FETCH completed` left the parsed email uninspected,
even though `email.body`, which is not gated on completion, still matched.

The capture contains five flows with complete email literals:

- A FETCH followed by FIN, with no tagged reply (empty EOF callback).
- A FETCH followed by an incomplete `A1 O` reply and FIN.
- An unacknowledged FETCH response, parsed during end-of-capture flushing.
- An APPEND whose literal is followed by an incomplete command suffix and FIN.
- An unacknowledged APPEND literal, parsed during end-of-capture flushing.

The email fields and body must match once per flow, and `imap.response` must
match each of the three FETCH responses. The incomplete suffixes must not
prevent inspection of already-parsed emails or cause parser errors.
