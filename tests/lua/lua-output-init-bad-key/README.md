Reproducer for lua: output script init() returning a table with a
non-string/number key. LuaScriptInit's lua_next loop continues without
popping the value when lua_tostring returns NULL, so the next lua_next
misreads the stack and SEGVs during output load (ASAN: SEGV in
luaH_next).

The engine starts and setup() runs with the fix.

Ticket: #9051.
