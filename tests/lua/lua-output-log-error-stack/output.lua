local config = require("suricata.config")

local fails = 2000
local calls = 0
local base = nil

function init(args)
    local needs = {}
    needs["protocol"] = "dns"
    return needs
end

function setup(args)
    file = assert(io.open(config.log_path() .. "/results.log", "w"))
    collectgarbage("collect")
    base = collectgarbage("count")
end

function log(args)
    calls = calls + 1
    if calls <= fails then
        -- unique message: prevents Lua short string interning
        error("forced failure " .. calls)
    end
end

function deinit()
    if base ~= nil and calls > fails then
        collectgarbage("collect")
        local growth = collectgarbage("count") - base
        if growth < 64 then
            file:write("OK growth=" .. string.format("%.1f", growth) .. "KB\n")
        else
            file:write("LEAK growth=" .. string.format("%.1f", growth) .. "KB\n")
        end
    else
        file:write("INSUFFICIENT calls=" .. tostring(calls) .. "\n")
    end
    file:close()
end
