-- read the rule of the last alert from deinit(): the packet alert the
-- engine handed to log() lived in a packet that is freed by now
local rule = require("suricata.rule")
local config = require("suricata.config")

function init(args)
    local needs = {}
    needs["type"] = "packet"
    needs["filter"] = "alerts"
    return needs
end

function setup(args)
end

function log(args)
end

function deinit(args)
    local f = assert(io.open(config.log_path() .. "/deinit-alert.log", "w"))
    local r, err = rule.get_rule()
    f:write("get_rule: " .. tostring(r and r:sid()) .. " " .. tostring(err) .. "\n")
    f:close()
end
