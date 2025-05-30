local flow = require("suricata.flow")
local dataset = require("suricata.dataset")
local dns = require("suricata.dns")
local logger = require("suricata.log")

function init (args)
    local needs = {}
    return needs
end

function thread_init (args)
    dns_new = dataset.new()
    ret, err = dns_new:get("dns-seen")
    if err ~= nil then
        logger.warning("dataset warning: " .. err)
        return 0
    end
end

function match (args)
    local f = flow.get()
    ipver, srcip, dstip, proto, sp, dp = f:tuple()
    local tx = dns.get_tx()
    query = tx:rrname()
    if query == nil then
        return 0
    end
    str = ipver .. ":<" .. srcip .. ">:<" .. dstip .. ">:" .. dp .. "--" .. query

    ret, err = dns_new:add(str, #str);
    if err ~= nil then
        logger.warning("lua warning " .. err)
        return 0
    end
    if ret == 1 then
        logger.notice(str .. " => " .. ret)
    end
    return ret
end
