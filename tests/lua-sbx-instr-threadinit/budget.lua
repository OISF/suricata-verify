-- thread_init() gets a fresh instruction budget (the fix), so a low
-- max-instructions does not stop engine start at thread setup.
local log = require('suricata.log')
function init(args) return {} end
function thread_init(args)
    local t = {}
    for i = 1, 50 do t[i] = i end
    return {}
end
function match(args)
    local s = string.char(65, 66, 67)
    log.warning("matched " .. #s)
    return 1
end
