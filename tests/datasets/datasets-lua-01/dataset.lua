local dataset = require "suricata.dataset"
local flow = require("suricata.flow")
local logger = require("suricata.log")

function init (args)
    local needs = {}
    needs["packet"] = tostring(true)
    return needs
end

function thread_init (args)
    conn_new, err = dataset.new()
    ret, err = conn_new:get("conn-seen")
    if err ~= nil then
        logger.warning("dataset warning: " .. err)
        return 0
    end
end

function match (args)
    local f = flow.get()
    ipver, srcip, dstip, proto, sp, dp = f:tuple()
    str = ipver .. ":<" .. srcip .. ">:<" .. dstip .. ">:" .. dp

    ret, err = conn_new:add(str, #str);
    if ret == 1 then
        logger.info(str .. " => " .. ret)
    end
    return ret
end
