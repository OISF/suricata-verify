-- alerts logger: index the (lazy, >32 points) points object in log() to
-- set the cursor, then index it again from deinit(), outside any callback
-- where the anchor tx is already gone
local dnp3 = require("suricata.dnp3")

function init(args)
    return { type = "packet", filter = "alerts" }
end

function setup(args)
end

function log(args)
    local tx = dnp3.get_tx()
    if tx == nil then
        return
    end
    local body = tx["request"] or tx["response"]
    if body == nil or body["objects"] == nil then
        return
    end
    for _, obj in pairs(body["objects"]) do
        if type(obj) == "table" and obj["points"] ~= nil and #obj["points"] > 32 then
            pts = obj["points"]
            local first = pts[1]
            print("log point 1: " .. tostring(first and first.index) .. " of " .. #pts)
        end
    end
end

function deinit(args)
    local p = pts and pts[2]
    print("deinit point 2: " .. tostring(p and p.index))
end
