Verify that with `app-layer.protocols.imap.max-tx=2`, creating a third live
IMAP transaction completes the oldest one with `too_many_transactions`, as in
MQTT and PGSQL, and that parsing goes on.

An invalid client line arriving while both transactions are live does not end
them, so a server literal being consumed keeps its octets, even one that looks
like a tagged reply.

A server reply matching no command, arriving while both transactions are live,
is dropped instead of ending one of them, and `too_many_transactions` is raised
once there is room for its transaction.
