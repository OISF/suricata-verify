local flowint = require("suricata.flowint")

function init(args)
    local vars = {}
    for i = 1, 15 do
        vars[i] = "mt_fi_" .. i
    end
    return { flowint = vars }
end

function match(args)
    local fi = flowint.get("mt_fi_15")
    if fi == nil then
        return 0
    end
    return 1
end
