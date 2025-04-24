local flowvarlib = require("suricata.flowvar")

function init (args)
    flowvarlib.register("key")
    return {}
end

function thread_init (args)
    var = flowvarlib.get("key")
end

function match(args)
    var:set("value", 5)
    return 1
end
