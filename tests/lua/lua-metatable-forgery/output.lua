local config = require("suricata.config")
local hashlib = require("suricata.hashlib")

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

    -- Give an md5 handle the sha256 metatable: every method then
    -- reinterprets the SCMd5 payload as an SCSha256.
    local ok = pcall(function()
        local h = hashlib.md5()
        -- setmetatable() only accepts tables in Lua 5.4; debug.setmetatable
        -- works on userdata
        debug.setmetatable(h, getmetatable(hashlib.sha256()))
        h:update("A")
        h:finalize()
    end)

    if ok then
        file:write("FORGERY ACCEPTED\n")
    else
        file:write("OK\n")
    end
    file:flush()
end

function deinit()
    file:close()
end
