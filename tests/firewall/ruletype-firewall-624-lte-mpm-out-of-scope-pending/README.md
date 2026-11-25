# LTE pending rule that is out of scope

Two `http1:<request_headers` accept rules. sid:211 is out of the flows scope by destination
address and carries a host the buffer never gets, so it is the lowest id the fast pattern
does not add; the address scope keeps it in the port group of the flow, which a port scope
would not. sid:212 is in scope and matches the Host of the first segment.

A rule the pattern did not add is pending at its hook and the walk has to behave as if it
were in the list, because it can still match as the tx advances. A rule that is out of scope
is not that rule: the walk inspects it, gets a header no match and carries on. So the accept
has to come from sid:212, and not from the default policies at the end of the tx.
