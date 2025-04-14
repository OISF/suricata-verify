local rule = require("suricata.rule")

function init(args)
    local needs = {}
    return needs
end

function match(args)
    local sig = rule.get_rule()
    local msg, prio = sig:class()

    if msg == "Potentially Bad Traffic" and prio == 2 then
        return 1
    else
        return 0
    end
end
