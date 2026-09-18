Reproducer for lua/http: LuaHttpGetHeader() uses lua_gettop() as the
argument index, so tx:request_header("Host", "junk") looks up "junk"
instead of "Host" (and a detached call uses an invalid stack index).

The script asserts the Host header value is returned even with an extra
argument.

Ticket: #9081.
