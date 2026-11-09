local bytevar = require("suricata.bytevar")

function init(args)
    bytevar.map(args, "uv")
    return {}
end

function match(args)
    local bv = bytevar.get("uv")
    local v = bv:value()
    -- the extractor has not run for this packet: value must be unset
    if v == nil or v == 0 then
        return 1
    end
    return 0
end
