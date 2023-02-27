local io = require("io")
function init(args)
    local needs = {}
    return needs
end

function match(args)
    msg, prio = SCRuleClass()

    if msg == "Potentially Bad Traffic" and prio == 2 then
        return 1
    else
        return 0
    end
end
