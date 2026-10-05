# IMAP APPEND body retention budget

Two APPENDs on one connection: a small message, then a message whose literal
exactly fills the per-transaction retention budget. The small body is retained
in full. The over-budget body is truncated to the remaining budget, keeping its
start-of-body prefix, so a rule matching the beginning of the body still alerts,
and the data_limit_reached event is raised. The literal is exactly at the body
limit, so body_too_large is not set.

Body-MD5 inspection must hash the final retained body: the small message's
hash remains unchanged, and the large message's hash covers its retained prefix
of 10485754 bytes (the 10 MiB budget minus the six-byte APPEND command). A rule
for the pre-truncation body's hash must not alert.
