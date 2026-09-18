local config = require("suricata.config")

function init(args)
    file = assert(io.open(config.log_path() .. "/results.log", "w"))

    -- All three entry points use GetLuaData() without a NULL check in
    -- output scripts, which never set the luaext_key_ld registry entry.
    local ok1 = pcall(function()
        require("suricata.flowint").register("out_fi")
    end)
    file:write("flowint=" .. tostring(ok1) .. "\n")

    local ok2 = pcall(function()
        require("suricata.flowvar").register("out_fv")
    end)
    file:write("flowvar=" .. tostring(ok2) .. "\n")

    local ok3 = pcall(function()
        require("suricata.bytevar").map(nil, "out_bv")
    end)
    file:write("bytevar=" .. tostring(ok3) .. "\n")
    file:flush()

    local needs = {}
    needs["type"] = "packet"
    return needs
end

function setup(args)
end

function log(args)
end

function deinit()
    file:close()
end
