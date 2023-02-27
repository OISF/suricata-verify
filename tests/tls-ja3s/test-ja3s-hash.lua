local io = require("io")
function init(args)
    local needs = {}
    needs["tls"] = tostring(true)
    return needs
end

function match(args)
    hash = Ja3SGetHash()
    if hash == nil then
        return 0
    end

    if hash == "5d79edf64e03689ff559a54e9d9487bc" then
        return 1
    end

    return 0
end
