local rule = require("suricata.rule")

function init(args)
    return {}
end

function match(args)
    local sig = rule.get_rule()
    local action = sig:action()

    if action == "alert" then
        return 1
    else
        return 0
    end
end
