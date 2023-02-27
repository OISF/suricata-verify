local io = require("io")
function init(args)
    local needs = {}
    needs["bytevar"] = {"var1", "var2"}
    return needs
end

function match(args)
    local var1 = SCByteVarGet(0)
    local var2 = SCByteVarGet(1)

    if var1 and var2 then
        if var1 == 0x48545450 and var2 == 0x2f312e31 then
            return 1
        end
    end
    return 0
end
