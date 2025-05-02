local ja3 = require("suricata.ja3")

function init(args)
    ja3.enable_ja3()
    local needs = {}
    needs["ja3s"] = true
    return needs
end

function match(args)
    local tx = ja3.get_tx()
    local str = tx:ja3s_get_string()
    if str == nil then
        return 0
    end

    if str == "771,49199,65281-0-11-16-23" then
        return 1
    end

    return 0
end
