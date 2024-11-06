function init (args)
    local needs = {}
    needs["packet"] = tostring(true)
    return needs
end

function thread_init (args)
    conn_new, err = dataset.new()
    ret, err = conn_new:get("conn-seen")
    if err ~= nil then
        SCLogWarning("dataset warning: " .. err)
        return 0
    end
end

function match (args)
    ipver, srcip, dstip, proto, sp, dp = SCFlowTuple()
    str = ipver .. ":<" .. srcip .. ">:<" .. dstip .. ">:" .. dp

    ret, err = conn_new:add(str, #str);
    if ret == 1 then
        SCLogInfo(str .. " => " .. ret)
    end
    return ret
end
