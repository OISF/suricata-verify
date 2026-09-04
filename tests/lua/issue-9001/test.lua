-- The garbage collector must not be reachable as a method on the
-- hasher, calling it frees the hash context while the hasher still
-- points at it.

local hashlib = require("suricata.hashlib")

function init(args)
    return {}
end

function match(args)
    local hashers = { hashlib.sha256(), hashlib.sha1(), hashlib.md5() }

    for _, hasher in ipairs(hashers) do
        if hasher.__gc ~= nil then
            return 0
        end

        -- The documented methods are still available.
        hasher:update("www.suricata-ids.org")
        hasher:finalize_to_hex()
    end

    return 1
end
