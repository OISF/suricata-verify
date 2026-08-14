-- Type-confusion guard for suricata.packet methods.
--
-- packet methods are plain functions on the packet metatable, so `p:tuple()`
-- is just sugar for `p.tuple(p)`. A script can call them with ANY value as the
-- first argument. On affected versions the methods fetch "self" with a raw
-- lua_touserdata() that performs NO type validation, then dereference it as a
-- `struct LuaPacket *`. Passing an unrelated userdata (here a flowint, whose
-- payload is a small integer) makes the reinterpreted `Packet *` point at
-- attacker-influenced memory, which the method dereferences -> the whole engine
-- takes SIGSEGV from inside the Lua sandbox.
--
-- After the fix each method validates the type with luaL_checkudata(), so the
-- wrong-type object raises a catchable Lua error ("suricata:packet expected,
-- got ...") on the first call below. lua_pcall catches it, the engine logs it
-- and runs to completion instead of crashing; match() never returns, so no
-- alert.

local packet = require("suricata.packet")
local flowint = require("suricata.flowint")

function init(args)
    flowint.register("x")
    return {}
end

function match(args)
    local p = packet.get()
    local wrong = flowint.get("x") -- foreign userdata, NOT a suricata:packet

    -- Every packet method must survive a wrong-type "self" without crashing.
    p.payload(wrong)
    p.pcap_cnt(wrong)
    p.timestring_legacy(wrong)
    p.timestamp(wrong)
    p.tuple(wrong)
    p.sp(wrong)
    p.dp(wrong)

    -- Not reached after the fix: the first call above raises. Present so that,
    -- on affected builds, a hypothetical survivor would still exercise the path.
    return 1
end
