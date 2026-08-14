local dataset = require("suricata.dataset")
local flowint = require("suricata.flowint")

function init(args)
    flowint.register("x")
    return {}
end

function match(args)
    local wrong = flowint.get("x") -- foreign userdata, NOT a dataset object
    
    -- Must survive a wrong-type object without crashing.
    dataset.add(wrong, "AAAA", 4)
    dataset.get(wrong, "no-such-set")
    return 1
end
