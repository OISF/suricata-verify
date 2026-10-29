local flowvar = require("suricata.flowvar")

function init(args)
    flowvar.register("ticket_8858")
    return { ["packet"] = true }
end

function thread_init(args)
    fv = flowvar.get("ticket_8858")
end

function match(args)
    fv:set("A", -1)
    return 1
end
