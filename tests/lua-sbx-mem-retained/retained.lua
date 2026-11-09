local log = require('suricata.log')
local kept = {}
function init(args) return {} end
function thread_init(args) return {} end
function match(args)
    -- retain memory across calls; must count against the max-bytes cap
    kept[#kept + 1] = string.rep('x', 16384)
    if #kept >= 6 then
        log.warning("retained " .. #kept)
        return 0
    end
    return 1
end
