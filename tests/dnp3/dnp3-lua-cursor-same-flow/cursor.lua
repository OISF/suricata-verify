-- Two invocations on the same flow. The first retains tx1's lazy points
-- userdata and indexes points[1], which sets the walk cursor. tx1 is freed
-- before the second invocation (on tx2) reads retained[2]: the cursor
-- belongs to the first invocation, so that access must re-resolve tx1 and
-- return nil instead of following tx1's freed point list.
local dnp3 = require("suricata.dnp3")
local logger = require("suricata.log")

local retained = nil
local done = false

function init(args)
    return {}
end

local function lazy_points()
    local tx = dnp3.get_tx()
    if tx == nil then
        return nil
    end
    local body = tx["request"] or tx["response"]
    if body == nil or body["objects"] == nil then
        return nil
    end
    for _, obj in pairs(body["objects"]) do
        if type(obj) == "table" and obj["points"] ~= nil
                and type(obj["points"]) ~= "table" then
            return obj["points"]
        end
    end
    return nil
end

function match(args)
    if done then
        return 0
    end
    local pts = lazy_points()
    if pts == nil then
        return 0
    end

    if retained == nil then
        -- first invocation: index points[1] (sets the cursor), then retain
        if pts[1] == nil then
            return 0
        end
        logger.notice("cursor-same-flow: call 1 point 1 of " .. #pts)
        retained = pts
        return 0
    end

    -- second invocation, same flow: index the retained value once
    done = true
    local p2 = retained[2]
    logger.notice("cursor-same-flow: call 2 retained point 2: " .. (p2 == nil and "nil" or "set"))
    if p2 == nil and pts[1] ~= nil then
        return 1
    end
    return 0
end
