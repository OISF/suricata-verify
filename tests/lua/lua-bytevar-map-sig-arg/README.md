Reproducer for lua/bytevar: map() validates only
lua_islightuserdata() on the first argument and then treats it as a
const Signature*. An unsandboxed output script can get other
lightuserdata values from debug.getregistry() and pass one as the
signature; DetectByteRetrieveSMVar() then walks s->init_data on the
forged pointer (ASAN: SEGV).

A forged pointer must be rejected with a clean Lua error.

Ticket: #9058.
