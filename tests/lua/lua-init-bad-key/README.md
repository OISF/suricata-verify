Reproducer for lua: init() returning a table with a non-string/number key.
Both DetectLuaSetupPrime and LuaScriptInit iterate the table with
lua_next and continue without popping the value when lua_tostring returns
NULL. The next lua_next reads the wrong stack slot and dereferences a
non-table (ASAN: SEGV in luaH_next), at rule/output load time.

The rule script loads and alerts with the fix.

Ticket: #9051.
