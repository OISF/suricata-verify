function transform(input, args)
    -- luaxform state has no DetectLuaData either
    require("suricata.flowint").register("xf_fi")
    return input, #input
end
