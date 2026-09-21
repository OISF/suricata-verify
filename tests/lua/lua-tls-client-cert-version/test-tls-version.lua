-- reproducer 9080: per-direction version in get_*_cert_info
local tls = require("suricata.tls")
local config = require("suricata.config")

local name = "tlsver_lua.log"
local file

function init (args)
    local needs = {}
    needs["protocol"] = "tls"
    return needs
end

function setup (args)
    filename = config.log_path() .. "/" .. name
    file = assert(io.open(filename, "a"))
end

function log (args)
    local t, err = tls.get_tx()
    if t == err then
        print(err)
        return
    end
    -- client hello carries 0x0301, server hello 0x0303: each direction
    -- must report its own version alongside its own certificate
    local cver, csubj = t:get_client_cert_info()
    local sver, ssubj = t:get_server_cert_info()
    file:write(string.format("client: %s %s  server: %s %s\n",
        tostring(cver), tostring(csubj), tostring(sver), tostring(ssubj)))
    file:flush()
end

function deinit (args)
    file:close(file)
end
