Test that an auto-accept-prior-states (`<hook`) rule whose address header does
not match the packet cannot cover an earlier app-layer hook.

The single-packet TLS ClientHello is from `10.16.1.11`. A normal matching
`accept:flow` at `client_hello_done` precedes an LTE rule at the same hook that
is restricted to `192.0.2.0/24`. Since the LTE rule is inapplicable,
`client_in_progress` must fall through to the default app policy and drop the
flow before the normal rule can accept it.

The buggy implementation counts the inapplicable LTE candidate before checking
its address, suppresses the prior-hook default drop, and lets the preceding
same-hook rule accept the flow.
