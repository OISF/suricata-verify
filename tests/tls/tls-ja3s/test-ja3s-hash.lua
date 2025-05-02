local ja3 = require("suricata.ja3")

function init(args)
    ja3.enable_ja3()
    local needs = {}
    needs["ja3s"] = true
    return needs
end

function match(args)
    local tx = ja3.get_tx()
    local hash = tx:ja3s_get_hash()
    if hash == nil then
        return 0
    end

    if hash == "5d79edf64e03689ff559a54e9d9487bc" then
        return 1
    end

    return 0
end
