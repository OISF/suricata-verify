Reproducer for lua/hashlib: all update/digest/hexdigest entry points
cast the Lua string length (size_t) to uint32_t before calling into the
Rust FFI, so a string larger than 4GiB is hashed only for len mod 2^32
bytes and the digest is silently wrong.

The output script hashes a 2^32+1 byte string (Lua's string.rep() is
capped at INT_MAX, so the string is read from /dev/zero). The call must
be rejected instead of returning a digest computed over a truncated
length.

This test allocates >4GiB, so it is skipped unless SV_LUA_HUGE is set in
the environment:

    SV_LUA_HUGE=1 ./run.py lua-hashlib-huge-len

Ticket: #9076.
