local bytevar = require("suricata.bytevar")
local config = require("suricata.config")

function init(args)
    local needs = {}
    needs["type"] = "packet"
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

    -- non-lightuserdata arguments must fail cleanly
    if pcall(bytevar.map, nil, "x") then
        file:write("NULL ACCEPTED\n")
        return
    end
    if pcall(bytevar.map, "string", "x") then
        file:write("STRING ACCEPTED\n")
        return
    end

    -- a lightuserdata that is not the init() signature pointer must also
    -- be rejected; the registry contains lightuserdata keys
    local forged = nil
    for k, _ in pairs(debug.getregistry()) do
        if type(k) == "userdata" then
            forged = k
            break
        end
    end
    if forged == nil then
        file:write("NOFORGE\n")
        return
    end

    if pcall(bytevar.map, forged, "whatever") then
        file:write("FORGED ACCEPTED\n")
    else
        file:write("OK\n")
    end
    file:flush()
end

function deinit()
    file:close()
end
