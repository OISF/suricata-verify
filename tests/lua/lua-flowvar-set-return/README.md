Reproducer for lua: LuaFlowvarSet()/LuaFlowintSet() end with "return 1"
without pushing a result, so the Lua call returns whatever value C left
on top of the Lua stack: the function's last argument, or (as observed)
the boolean flow-lock-hint left behind by LuaStateGetFlow(). The
documented API returns nothing.

The script asserts a successful set() does not hand back an unrelated
value (its argument or a boolean false).

Ticket: #9072.
