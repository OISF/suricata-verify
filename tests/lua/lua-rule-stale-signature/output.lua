local config = require("suricata.config")
local rule = require("suricata.rule")

local cached = nil

function init(args)
    local needs = {}
    needs["type"] = "packet"
    needs["filter"] = "alerts"
    return needs
end

function setup(args)
    file = assert(io.open(config.log_path() .. "/results.log", "w"))
end

function log(args)
    local s = rule.get_rule()
    if cached == nil then
        cached = s
    end
    file:write("sid=" .. tostring(cached:sid()) .. "\n")
    file:flush()
end

function deinit()
    file:write("done\n")
    file:close()
end
