local flow = require("suricata.flow")
local flowint = require("suricata.flowint")

function init(args)
    flowint.register("x")
    return {}
end

function match(args)
    local f = flow.get()
    local wrong = flowint.get("x") -- foreign userdata, NOT a suricata:flow

    -- Every flow method must survive a wrong-type "self" without crashing.
    f.id(wrong)
    f.app_layer_proto(wrong)
    f.has_alerts(wrong)
    f.stats(wrong)
    f.tuple(wrong)
    f.timestamps(wrong)

    return 1
end
