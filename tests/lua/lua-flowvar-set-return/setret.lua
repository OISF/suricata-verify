local flowvar = require("suricata.flowvar")
local flowint = require("suricata.flowint")

function init(args)
    return { flowvar = { "setret_fv" }, flowint = { "setret_fi" } }
end

function match(args)
    -- set() must not hand back an arbitrary value from the C stack
    -- contract (the argument, or the boolean leaked by LuaStateGetFlow)
    local fv = flowvar.get("setret_fv")
    local r1 = fv:set("abc")
    if r1 == "abc" or r1 == false then
        return 0
    end

    local fi = flowint.get("setret_fi")
    local r2 = fi:set(5)
    if r2 == 5 or r2 == false then
        return 0
    end

    return 1
end
