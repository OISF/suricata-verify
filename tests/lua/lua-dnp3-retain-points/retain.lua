local dnp3 = require("suricata.dnp3")

-- The lazy points userdata of the first connection's large object is retained
-- in this module global. The first connection's flow (and its DNP3 state,
-- which owns the transaction the userdata references) is freed before the
-- second connection's callback runs, so the retained value must be invalidated
-- by the lifetime check when it is accessed.
local retained = nil
local alerted = false

function init(args)
    return {}
end

function match(args)
    if alerted then
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

    local pts
    for _, obj in pairs(body["objects"]) do
        if type(obj) == "table" and obj["points"] ~= nil
                and type(obj["points"]) ~= "table" then
            pts = obj["points"]
            break
        end
    end
    if pts == nil then
        return 0
    end

    if retained == nil then
        -- first connection: retain the lazy points userdata
        retained = pts
        return 0
    end

    -- second connection: the first connection's transaction has been freed.
    -- The retained userdata must read as nil (lifetime check failed) while
    -- this connection's own points value is still alive.
    if retained[1] == nil and pts[1] ~= nil then
        alerted = true
        return 1
    end
    return 0
end
