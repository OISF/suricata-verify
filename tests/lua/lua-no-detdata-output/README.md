Reproducer for lua: flowint/flowvar register() and bytevar map() deref
GetLuaData() without a NULL check. Output lua states never set the
luaext_key_ld registry entry, so the calls SEGV the engine during output
init (ASAN: SEGV in LuaFlowintRegister).

With the NULL check in place the calls raise Lua errors, which the script
catches with pcall and reports.

Ticket: #9050.
