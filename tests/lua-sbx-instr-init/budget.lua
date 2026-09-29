-- light init(): a few allocations only, well within a per-call budget.
-- Without the per-call reset the accumulated load/init budget trips a low
-- max-instructions; with the reset init() gets a fresh budget and succeeds.
local log = require('suricata.log')
function init(args)
    local t = {}
    for i = 1, 50 do t[i] = i end
    return {}
end
function thread_init(args)
    local s = ''
    for i = 1, 50 do s = s .. 'x' end
    return {}
end
function match(args)
    local s = string.char(65, 66, 67)
    log.warning("matched " .. #s)
    return 1
end
