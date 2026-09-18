local config = require("suricata.config")
local flowint = require("suricata.flowint")

function init(args)
    local needs = {}
    needs["protocol"] = "dns"
    return needs
end

function setup(args)
    file = assert(io.open(config.log_path() .. "/results.log", "w"))
end

function log(args)
    if checked then
        return
    end
    checked = true

    local fi = flowint.get("big")
    local ok = pcall(function()
        fi:set(4294967296)
    end)
    if not ok then
        file:write("REJECTED\n")
    else
        local v = fi:value()
        if v == 4294967296 then
            file:write("ROUNDTRIP\n")
        else
            file:write("TRUNCATED " .. tostring(v) .. "\n")
        end
    end
    file:close()
end

function deinit()
end
