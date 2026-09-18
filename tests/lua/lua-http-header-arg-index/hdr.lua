local http = require("suricata.http")

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if tx == nil then
        return 0
    end

    -- the extra argument must not change the lookup key
    local v = tx:request_header("Host", "junk")
    if v == "testmyids.org" then
        return 1
    end
    return 0
end
