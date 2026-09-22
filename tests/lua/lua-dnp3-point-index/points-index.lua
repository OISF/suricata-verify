local dnp3 = require("suricata.dnp3")

function init(args)
    return {}
end

function match(args)
    local tx = dnp3.get_tx()
    if tx == nil then return 0 end
    local body = tx["request"] or tx["response"]
    if body == nil or body["objects"] == nil then return 0 end
    local points
    for _, obj in pairs(body["objects"]) do
        if type(obj) == "table" and obj["points"] ~= nil then
            points = obj["points"]
            break
        end
    end
    if points == nil then return 0 end
    -- position 1 holds the first wire point (index 0), position 2 the
    -- second (index 1); the last position holds the last wire index
    local n = #points
    if n ~= 65528 then return 0 end
    if points[1] == nil or points[1].index ~= 0 then return 0 end
    if points[2] == nil or points[2].index ~= 1 then return 0 end
    if points[n] == nil or points[n].index ~= n - 1 then return 0 end
    -- out of bounds stays nil: the walk cannot read past the count
    if points[n + 1] ~= nil then return 0 end
    -- a 1..n walk yields every point in wire order, exactly once
    for i = 1, n do
        local pt = points[i]
        if pt == nil or pt.index ~= i - 1 then return 0 end
    end
    return 1
end
