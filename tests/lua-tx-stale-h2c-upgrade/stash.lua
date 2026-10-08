-- h2c upgrade stale-handle pin: the first (HTTP/1) tx stashes its live
-- handle; once the upgrade swaps the app-layer state, the stashed handle
-- must fail closed. Without the alproto/flow-id pin in the anchor, the
-- HTTP/1 handle passes the checks on the upgraded flow and the accessor
-- walks an HTTP2Transaction (type confusion).
local http = require("suricata.http")
local stash = nil

function init(args)
    return {}
end

function match(args)
    if stash == nil then
        -- first (HTTP/1) tx: the flow alproto is still HTTP/1, so
        -- http.get_tx() is live here; stash the handle and alert on it
        local tx = http.get_tx()
        if tx == nil then
            return 0
        end
        stash = tx
        return 1
    end
    -- after the upgrade the stashed HTTP/1 handle must fail closed: a
    -- raise gives the "tx no longer valid" error, a non-nil result would
    -- be the type confusion
    local h = stash:request_headers()
    if h ~= nil then
        error("stale h2c handle resolved: " .. tostring(h))
    end
    return 0
end
