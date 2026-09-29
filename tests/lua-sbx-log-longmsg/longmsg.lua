local log = require('suricata.log')
function init(args) return {} end
function thread_init(args) return {} end
function match(args)
    -- a very long message; must log cleanly (no stack over-read / truncation crash)
    local s = string.rep('A', 16384)
    log.warning("long " .. #s)
    return 1
end
