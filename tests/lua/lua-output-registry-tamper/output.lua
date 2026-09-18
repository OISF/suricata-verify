local dns = require("suricata.dns")
local config = require("suricata.config")

local calls = 0
local snap = nil

function init(args)
    local needs = {}
    needs["protocol"] = "dns"
    return needs
end

function setup(args)
    file = assert(io.open(config.log_path() .. "/results.log", "w"))
end

function log(args)
    calls = calls + 1
    local reg = debug.getregistry()
    if calls == 1 then
        snap = {}
        for k, v in pairs(reg) do
            if type(k) == "userdata" then
                snap[k] = v
            end
        end
        return
    end
    if calls > 2 then
        return
    end

    -- keys whose value changed between events are the per-event tx and
    -- packet entries; retype them with a context pointer from another
    -- registry entry
    local changed = {}
    local unchanged = {}
    for k, v in pairs(reg) do
        if type(k) == "userdata" then
            if snap[k] ~= v then
                changed[#changed + 1] = k
            else
                unchanged[#unchanged + 1] = v
            end
        end
    end

    for _, v in ipairs(unchanged) do
        for _, k in ipairs(changed) do
            reg[k] = v
        end
        local ok, tx = pcall(dns.get_tx)
        if ok and tx ~= nil then
            pcall(function()
                return tx:rrname()
            end)
        end
    end

    file:write("done\n")
    file:flush()
end

function deinit()
    file:close()
end
