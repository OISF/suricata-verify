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

local function disabled(fn, s)
    local ok, r = pcall(fn, s)
    if not ok then
        return true
    end
    return r == nil
end

function log(args)
    if checked then
        return
    end
    checked = true

    if disabled(hashlib.md5_hexdigest, "abc") and
       disabled(hashlib.sha256_hexdigest, "abc") and
       disabled(hashlib.md5_digest, "abc") then
        file:write("OK\n")
    else
        file:write("WORKED\n")
    end
    file:close()
end

function deinit()
end
