local rule = require("suricata.rule")

function init(args)
    return {}
end

function match(args)
    local sig = rule.get_rule()
    local sid = sig:sid()
    local rev = sig:rev()
    local gid = sig:gid()

    if sid == 1 and rev == 7 and gid == 1 then
        return 1
    else
        return 0
    end
end
