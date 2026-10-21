-- pairs() over the dnp3 points value must yield (position, point
-- table) for 1..#points on both sides of the 32-point eager
-- threshold: request 1 is 33 points (lazy userdata), request 2 is 32
-- points (plain table). Before the __pairs fix the first loop raises
-- (no __pairs on the lazy value) and only the 32-point alert fires.
local dnp3 = require("suricata.dnp3")
local logger = require("suricata.log")

local done33 = false
local done32 = false

function init(args)
    return {}
end

local function check_points(tag, pts, expect, lazy)
    if type(pts) ~= lazy then
        return false
    end
    if #pts ~= expect then
        return false
    end
    local count = 0
    for i, p in pairs(pts) do
        if i ~= count + 1 or type(p) ~= "table" or p["index"] ~= i then
            return false
        end
        count = count + 1
    end
    if count ~= expect then
        return false
    end
    logger.notice(tag .. " count=" .. count .. " ok")
    return true
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

    for _, obj in pairs(body["objects"]) do
        if type(obj) == "table" and obj["points"] ~= nil then
            local n = #obj["points"]
            if n == 33 and not done33 then
                if check_points("points-pairs: 33 lazy", obj["points"], 33, "userdata") then
                    done33 = true
                    return 1
                end
            elseif n == 32 and not done32 then
                if check_points("points-pairs: 32 table", obj["points"], 32, "table") then
                    done32 = true
                    return 1
                end
            end
        end
    end
    return 0
end
