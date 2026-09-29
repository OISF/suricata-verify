-- probe.lua: the cheapest possible allocation
local log = require('suricata.log')
function init(args) return {} end
function thread_init(args) return {} end
function match(args)
    local s = string.char(65, 66, 67)
    log.warning("allocated " .. #s)
    return 1
end
