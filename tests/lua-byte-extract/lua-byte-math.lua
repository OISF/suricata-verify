function init(args)
    local needs = {}
    needs["bytevar"] = {"var2"}
    return needs
end

function match(args)
    local var2 = SCByteVarGet(0)

    if string.pack(">i4", var2) == "HTTP" then
        return 1
    else
        return 0
    end
end
