local io = require("io")
function init(args)
    local needs = {}
    needs["tls"] = tostring(true)
    return needs
end

function match(args)
    str = Ja3SGetString()
    if str == nil then
        return 0
    end

    if str == "771,49199,65281-0-11-16-23" then
        return 1
    end

    return 0
end
