local flowvar = require("suricata.flowvar")

function init (args)
    return {}
end

function thread_init (args)
    testvar = flowvar.get("TestVar")
end

function match(args)
    print "Before loading Variable"
    local value = testvar:value()
    if value == nil then
       print("TestVar has no value")
       return 0
    end

    if value ~= "/zib100/zib100.json?origin=orf.at HTTP/1.1" then
       print("TestVar has wrong value")
       return 0
    end

    return 1
end
