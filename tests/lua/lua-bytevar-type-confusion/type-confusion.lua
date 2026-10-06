local bytevar = require("suricata.bytevar")
local hashing = require("suricata.hashlib")

function init(args)
    local wrong = hashing.sha256()
    bytevar.map(wrong, "var1")
    return {}
end

function match(args)
    return 0
end
