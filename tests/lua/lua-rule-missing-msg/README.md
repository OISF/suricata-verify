Reproducer for ticket 9060 (msg-less path): a msg-less rule using the
rule lib; rule.get_rule() then sig:msg() must return "" for a signature
without msg. Pre-fix the getter pushed nil for the NULL msg.
