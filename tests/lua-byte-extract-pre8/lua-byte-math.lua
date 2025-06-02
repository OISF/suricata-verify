function init(args)
    local needs = {}
    needs["bytevar"] = {"var2"}
    return needs
end

function match(args)
    local var2 = SCByteVarGet(0)

    if var2 and var2 == 0x48545450 then
        return 1
    end

    return 0
end
