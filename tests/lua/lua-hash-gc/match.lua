local hashing = require("suricata.hashlib")

function init(args)
    return { payload = true }
end

function match(args)
    local h = hashing.sha256()
    h:update("before free")
    h:__gc()
    h:update("after free")
    h:__gc()
    return 0
end
