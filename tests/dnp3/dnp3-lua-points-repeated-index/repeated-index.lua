-- Repeated reads of the same points index must return the same
-- point: pin the invocation-local cursor's same-position path with a
-- 1..n walk that reads points[i] twice per iteration on the
-- 16384-point object.
local dnp3 = require("suricata.dnp3")

local done = false

function init(args)
    return {}
end

function match(args)
    if done then
        return 0
    end
    local tx = dnp3.get_tx()
    if tx == nil then
        return 0
    end
    local body = tx["request"] or tx["response"]
    if body == nil or body["objects"] == nil then
        return 0
    end
    for _, obj in pairs(body["objects"]) do
        if type(obj) == "table" and obj["points"] ~= nil then
            local pts = obj["points"]
            local n = #pts
            if n ~= 16384 then
                return 0
            end
            for i = 1, n do
                local a = pts[i]
                local b = pts[i]
                if a == nil or b == nil then
                    print("repeated-index: n=" .. n .. " bad read at " .. i)
                    return 0
                end
                if a["index"] ~= b["index"] or a["index"] ~= i then
                    print("repeated-index: n=" .. n .. " index mismatch at " .. i)
                    return 0
                end
            end
            print("repeated-index: n=" .. n .. " ok")
            done = true
            return 1
        end
    end
    return 0
end
