Reproducer for lua/smtp: get_tx() ignores the current tx id and returns
state->curr_tx, which already points at the next pipelined mail, so the
tx#0 callback reports tx#1's MAIL FROM.

The test asserts each tx reports its own MAIL FROM (alice then bob).

Ticket: #9067.
