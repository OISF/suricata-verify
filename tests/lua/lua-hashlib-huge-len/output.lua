local config = require("suricata.config")
local hashlib = require("suricata.hashlib")

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

    -- 2^32 + 1 bytes: string.rep() is capped at INT_MAX, so read from
    -- /dev/zero (the test is opt-in)
    local f = assert(io.open("/dev/zero", "rb"))
    local s = f:read(4294967297)
    f:close()

    local ok, res = pcall(hashlib.md5_hexdigest, s)
    if ok and res ~= nil then
        file:write("TRUNCATED\n")
    else
        file:write("REJECTED\n")
    end
    s = nil
    collectgarbage("collect")
    file:close()
end

function deinit()
end
