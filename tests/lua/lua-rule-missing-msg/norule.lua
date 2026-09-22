local rule = require("suricata.rule")

function init(args)
    return {}
end

function match(args)
    local s = rule.get_rule()
    if s == nil then return 0 end
    -- the rule has no msg keyword: the getter must report "" (not nil)
    if s:msg() ~= "" then return 0 end
    return 1
end
