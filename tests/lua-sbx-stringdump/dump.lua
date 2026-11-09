-- dump.lua: string.dump must be blocked
local log = require('suricata.log')
function init(args) return {} end
function thread_init(args) return {} end
function match(args)
    local secret = "value-of-no-use-but-still"
    local f = function() return secret end
    local b = string.dump(f)          -- must raise
    log.warning("dumped " .. #b .. " bytes")
    return 1
end
