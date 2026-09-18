local dns = require("suricata.dns")
local config = require("suricata.config")

function init(args)
    local needs = {}
    needs["protocol"] = "dns"
    return needs
end

function setup(args)
    file = assert(io.open(config.log_path() .. "/results.log", "w"))
end

function log(args)
    local tx = dns.get_tx()
    if tx ~= nil then
        file:write("RD=" .. tostring(tx:recursion_desired()) .. "\n")
    end
    file:flush()
end

function deinit()
    file:close()
end
