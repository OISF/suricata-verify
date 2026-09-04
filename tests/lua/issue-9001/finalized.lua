-- Finalizing consumes the hash context, using the hasher afterwards
-- must raise an error instead of using the free'd context.

local hashlib = require("suricata.hashlib")

function init(args)
    return {}
end

function match(args)
    local hasher = hashlib.sha256()
    hasher:update("www.suricata-ids.org")
    hasher:finalize()

    hasher:update("www.suricata-ids.org")

    return 1
end
