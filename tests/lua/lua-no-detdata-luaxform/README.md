Reproducer for lua: flowint register() (and friends) deref
GetLuaData() without a NULL check. luaxform scripts never get
DetectLuaData, so the transform SEGVs the engine when the script calls
register() (ASAN: SEGV in LuaFlowintRegister).

With the NULL check the transform call raises a Lua error, is skipped,
and the original URI still matches.

Ticket: #9050.
