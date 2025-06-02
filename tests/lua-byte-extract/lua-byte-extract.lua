local bytevars = require("suricata.bytevar")

function init(sig)
    bytevars.map(sig, "var1")
    bytevars.map(sig, "var2")
    return {}
end

function thread_init()
    bv0 = bytevars.get("var1")
    bv1 = bytevars.get("var2")
end

function match(args)
    local var1 = bv0:value()
    local var2 = bv1:value()

    if var1 and var2 then
        if var1 == 0x48545450 and var2 == 0x2f312e31 then
            return 1
        end
    end
    return 0
end
