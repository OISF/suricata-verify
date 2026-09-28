# relative pcre after a keyword that moves the detection pointer

A relative pcre (`pcre:"/re/R"`) following `byte_jump`, `byte_extract` or
`byte_math` used to be rejected at load time with

    pcre with /R (relative) needs preceding match in the same buffer

because only a preceding `content` or `pcre` counted as the match the relative
match is anchored on. Those 3 keywords all update the detection pointer, so a
relative match after them is anchored just as well.

The keywords are the only match condition of each rule, so the payload of the
pcap determines where the detection pointer ends up. See writepcap.py, which
generated input.pcap.

Redmine #7987.
