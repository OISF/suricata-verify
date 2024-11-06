function init (args)
    local needs = {}
    needs["dns.request"] = tostring(true)
    return needs
end

function thread_init (args)
    dns_new, err = dataset.get_ref("dns-seen")
    if err ~= nil then
        SCLogWarning("dataset warning: " .. err)
        return 0
    end
end

function match (args)
    ipver, srcip, dstip, proto, sp, dp = SCFlowTuple()
    query = DnsGetDnsRrname()
    if query == nil then
        return 0
    end
    str = ipver .. ":<" .. srcip .. ">:<" .. dstip .. ">:" .. dp .. "--" .. query

    ret, err = dataset.add(dns_new, str, #str);
    if err ~= nil then
        SCLogWarning("lua warning " .. err)
        return 0
    end
    if ret == 1 then
        SCLogNotice(str .. " => " .. ret)
    end
    return ret
end
