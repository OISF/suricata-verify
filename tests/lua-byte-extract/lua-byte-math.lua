local bytevars = require("suricata.bytevar")

function init(sig)
    bytevars.map(sig, "var2")
    return {}
end

function thread_init()
    bv2 = bytevars.get("var2")
end

function match(args)
    local var2 = bv2:value()

    if var2 and var2 == 0x48545450 then
        return 1
    end

    return 0
end
