-- Read membership back out of a PRELOADED dataset from Lua.
local dataset = require("suricata.dataset")
local dns = require("suricata.dns")
local logger = require("suricata.log")

function init(args)
    return {}
end

function thread_init(args)
    hosts = dataset.new()
    local _, err = hosts:get("known-hosts")
    if err ~= nil then
        logger.warning("dataset get failed: " .. err)
    end
end

function match(args)
    local tx = dns.get_tx()
    if tx == nil then
        return 0
    end
    local name = tx:rrname()
    if name == nil then
        return 0
    end

    -- Read back the preloaded entry: must already be present -> 0.
    local present = hosts:add(name, #name)

    -- A value that was never loaded: must be reported as newly added -> 1.
    local fresh = "absent-" .. name
    local absent = hosts:add(fresh, #fresh)

    logger.notice("known-hosts fetch: present=" .. tostring(present) ..
        " absent=" .. tostring(absent))

    if present == 0 and absent == 1 then
        return 1
    end
    return 0
end
