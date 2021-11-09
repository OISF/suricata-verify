function init(args)
    local needs = {}
    needs["bytevar"] = {"var1", "var2"}
    return needs
end

function match(args)
    local var1 = SCByteVarGet(0)
    local var2 = SCByteVarGet(1)

    if string.pack(">i4", var1) == "HTTP" and string.pack(">i4", var2) == "/1.1" then
        return 1
    else 
        return 0
    end
end
