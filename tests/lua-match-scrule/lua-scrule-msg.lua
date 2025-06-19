local rule = require("suricata.rule")

function init(args)
    return {}
end

function match(args)
    local sig = rule.get_rule()
    local msg = sig:msg()

    if msg == "FOO" then
        return 1
    else
        return 0
    end
end
