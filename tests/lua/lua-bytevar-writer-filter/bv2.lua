local bytevar = require("suricata.bytevar")

function init(args)
    bytevar.map(args, "uv")
    return {}
end

function match(args)
    local bv = bytevar.get("uv")
    local v = bv:value()
    -- tx-phase read: sid:1 (lower sid, evaluated first) already wrote
    -- the shared slot 0 this run; that value is not mine to read. My
    -- own extractor is ordered after this lua keyword, so the writer
    -- filter must report the slot unset here.
    if v == nil then
        return 1
    end
    return 0
end
