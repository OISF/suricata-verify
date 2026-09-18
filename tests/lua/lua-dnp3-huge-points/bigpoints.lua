local dnp3 = require("suricata.dnp3")

function init(args)
    return {}
end

function match(args)
    local tx = dnp3.get_tx()
    if tx == nil then
        return 0
    end

    local body = tx["request"] or tx["response"]
    if body == nil or body["objects"] == nil then
        return 0
    end

    local points = 0
    for _, obj in pairs(body["objects"]) do
        if type(obj) == "table" and obj["points"] ~= nil then
            points = points + #obj["points"]
        end
    end

    if points > 0 then
        return 1
    end
    return 0
end
